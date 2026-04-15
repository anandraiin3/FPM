"""
Embedding + ChromaDB storage for enriched chunks.

Uses OpenAI text-embedding-3-small for all embeddings.
ChromaDB persists to disk so the knowledge base survives restarts.
"""
import logging
import os

import chromadb
from openai import OpenAI

logger = logging.getLogger(__name__)

EMBEDDING_MODEL = "text-embedding-3-small"

# ChromaDB collection names (one per chunking strategy)
COLLECTION_PER_CONTROL = "controls_per_control"
COLLECTION_PER_LAYER = "controls_per_layer"
COLLECTION_PER_ATTACK = "controls_per_attack"


class KnowledgeStore:
    """Manages ChromaDB collections and embeddings."""

    def __init__(self, openai_client: OpenAI, persist_dir: str | None = None):
        self._openai = openai_client
        persist_dir = persist_dir or os.getenv("CHROMADB_PERSIST_DIR", "./chroma_data")
        self._chroma = chromadb.PersistentClient(path=persist_dir)
        logger.info("ChromaDB initialised at %s", persist_dir)

    def get_collection(self, name: str) -> chromadb.Collection:
        return self._chroma.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )

    def embed_text(self, text: str) -> list[float]:
        """Get embedding for a single text."""
        # text-embedding-3-small has 8192 token limit; truncate long texts
        truncated = _truncate_for_embedding(text)
        response = self._openai.embeddings.create(
            input=truncated,
            model=EMBEDDING_MODEL,
        )
        return response.data[0].embedding

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Get embeddings for a batch of texts (max 2048 per call)."""
        all_embeddings: list[list[float]] = []
        batch_size = 5  # small batch size to avoid token-per-batch limits
        for i in range(0, len(texts), batch_size):
            batch = [_truncate_for_embedding(t) for t in texts[i : i + batch_size]]
            response = self._openai.embeddings.create(
                input=batch,
                model=EMBEDDING_MODEL,
            )
            all_embeddings.extend([d.embedding for d in response.data])
        return all_embeddings

    def store_chunks(self, collection_name: str, chunks: list[dict]) -> int:
        """
        Store enriched chunks in a ChromaDB collection.
        Returns number of chunks stored.
        """
        if not chunks:
            return 0

        collection = self.get_collection(collection_name)

        # Check if already populated (idempotent)
        existing = collection.count()
        if existing >= len(chunks):
            logger.info(
                "Collection '%s' already has %d items (>= %d chunks), skipping",
                collection_name, existing, len(chunks),
            )
            return 0

        ids = [c["chunk_id"] for c in chunks]
        texts = [c["text"] for c in chunks]
        metadatas = [c.get("metadata", {}) for c in chunks]

        # Ensure metadata values are simple types for ChromaDB
        clean_metadatas = []
        for m in metadatas:
            clean = {}
            for k, v in m.items():
                if isinstance(v, (str, int, float, bool)):
                    clean[k] = v
                elif isinstance(v, list):
                    clean[k] = ", ".join(str(x) for x in v)
                else:
                    clean[k] = str(v)
            clean_metadatas.append(clean)

        logger.info("Embedding %d chunks for collection '%s'...", len(texts), collection_name)
        embeddings = self.embed_texts(texts)

        collection.add(
            ids=ids,
            documents=texts,
            embeddings=embeddings,
            metadatas=clean_metadatas,
        )
        logger.info("Stored %d chunks in '%s'", len(chunks), collection_name)
        return len(chunks)

    def query(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 10,
    ) -> list[dict]:
        """Dense vector search against a collection."""
        collection = self.get_collection(collection_name)
        if collection.count() == 0:
            return []

        query_embedding = self.embed_text(query_text)
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=min(n_results, collection.count()),
            include=["documents", "metadatas", "distances"],
        )

        hits = []
        for i in range(len(results["ids"][0])):
            hits.append({
                "chunk_id": results["ids"][0][i],
                "text": results["documents"][0][i],
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "distance": results["distances"][0][i] if results["distances"] else 0.0,
            })
        return hits


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAX_EMBED_CHARS = 20_000  # ~5k tokens at ~4 chars/token, safe under 8192 limit


def _truncate_for_embedding(text: str) -> str:
    """Truncate text to fit within the embedding model's token limit."""
    if len(text) <= _MAX_EMBED_CHARS:
        return text
    logger.debug("Truncating text from %d to %d chars for embedding", len(text), _MAX_EMBED_CHARS)
    return text[:_MAX_EMBED_CHARS]
