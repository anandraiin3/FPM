"""
Knowledge base builder — orchestrates parsing → chunking → enrichment → embedding.
"""
import logging
import os

from openai import OpenAI

from fpm.parsers.terraform_parser import parse_terraform
from fpm.parsers.nginx_parser import parse_nginx
from fpm.parsers.modsecurity_parser import parse_modsecurity
from fpm.parsers.kong_parser import parse_kong
from fpm.knowledge.chunking import chunk_per_control, chunk_per_layer, chunk_per_attack_type
from fpm.knowledge.enrichment import enrich_chunks
from fpm.knowledge.embeddings import (
    KnowledgeStore,
    COLLECTION_PER_CONTROL,
    COLLECTION_PER_LAYER,
    COLLECTION_PER_ATTACK,
)

logger = logging.getLogger(__name__)

# Default infrastructure directory (relative to project root)
_INFRA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "infrastructure")


def build_knowledge_base(
    openai_client: OpenAI,
    infra_dir: str | None = None,
    persist_dir: str | None = None,
) -> KnowledgeStore:
    """
    Parse all infrastructure configs, chunk, enrich, embed, and store.

    Returns the KnowledgeStore instance for retrieval.
    """
    infra_dir = infra_dir or _INFRA_DIR
    store = KnowledgeStore(openai_client, persist_dir=persist_dir)

    # Check if already built (idempotent)
    col = store.get_collection(COLLECTION_PER_CONTROL)
    if col.count() > 0:
        logger.info("Knowledge base already populated (%d items). Skipping build.", col.count())
        return store

    logger.info("Building knowledge base from %s", infra_dir)

    # ── Step 1: Parse all configs ──
    all_controls: list[dict] = []

    tf_dir = os.path.join(infra_dir, "terraform")
    for f in _find_files(tf_dir, ".tf"):
        all_controls.extend(parse_terraform(f))

    nginx_dir = os.path.join(infra_dir, "nginx")
    for f in _find_files(nginx_dir, ".conf"):
        if "modsecurity" in os.path.basename(f).lower():
            all_controls.extend(parse_modsecurity(f))
        else:
            all_controls.extend(parse_nginx(f))

    kong_dir = os.path.join(infra_dir, "kong")
    for f in _find_files(kong_dir, ".yaml", ".yml"):
        all_controls.extend(parse_kong(f))

    logger.info("Parsed %d controls from infrastructure configs", len(all_controls))

    # ── Step 2: Chunk (strategy 1 — per control) ──
    per_control_chunks = chunk_per_control(all_controls)
    logger.info("Strategy 1 (per_control): %d chunks", len(per_control_chunks))

    # ── Step 3: Chunk (strategy 2 — per layer) ──
    per_layer_chunks = chunk_per_layer(all_controls)
    logger.info("Strategy 2 (per_layer): %d chunks", len(per_layer_chunks))

    # ── Step 4: Enrich per-control chunks ──
    logger.info("Enriching %d per-control chunks via LLM...", len(per_control_chunks))
    enrich_chunks(per_control_chunks, openai_client)

    # ── Step 5: Chunk (strategy 3 — per attack type, requires enrichment) ──
    per_attack_chunks = chunk_per_attack_type(per_control_chunks)
    logger.info("Strategy 3 (per_attack_type): %d chunks", len(per_attack_chunks))

    # ── Step 6: Embed and store all three sets ──
    stored = 0
    stored += store.store_chunks(COLLECTION_PER_CONTROL, per_control_chunks)
    stored += store.store_chunks(COLLECTION_PER_LAYER, per_layer_chunks)
    stored += store.store_chunks(COLLECTION_PER_ATTACK, per_attack_chunks)

    logger.info("Knowledge base built: %d total chunks stored across 3 collections", stored)
    return store


def _find_files(directory: str, *extensions: str) -> list[str]:
    """Find all files with given extensions in a directory."""
    if not os.path.isdir(directory):
        logger.warning("Directory not found: %s", directory)
        return []
    files = []
    for fname in sorted(os.listdir(directory)):
        if any(fname.endswith(ext) for ext in extensions):
            files.append(os.path.join(directory, fname))
    return files
