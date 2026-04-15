"""
Hybrid retrieval: BM25 sparse + ChromaDB dense + cross-encoder reranking.

Flow:
  1. Rewrite the raw alert into an optimised retrieval query (cached per alert).
  2. Run BM25 keyword search over raw chunk texts.
  3. Run ChromaDB dense (vector) search.
  4. Merge candidates, deduplicate.
  5. Rerank with cross-encoder/ms-marco-MiniLM-L-6-v2.
  6. Return top-k results.
"""
import logging
from functools import lru_cache

from rank_bm25 import BM25Okapi
from sentence_transformers import CrossEncoder

from fpm.knowledge.embeddings import (
    KnowledgeStore,
    COLLECTION_PER_CONTROL,
    COLLECTION_PER_LAYER,
    COLLECTION_PER_ATTACK,
)

logger = logging.getLogger(__name__)

# Cross-encoder reranker (loaded once)
_reranker: CrossEncoder | None = None


def _get_reranker() -> CrossEncoder:
    global _reranker
    if _reranker is None:
        logger.info("Loading cross-encoder reranker model...")
        _reranker = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
        logger.info("Reranker loaded")
    return _reranker


class HybridRetriever:
    """Combines BM25, ChromaDB dense search, and cross-encoder reranking."""

    def __init__(self, store: KnowledgeStore):
        self._store = store
        self._bm25_corpus: list[dict] | None = None
        self._bm25_index: BM25Okapi | None = None
        self._build_bm25_index()

    def _build_bm25_index(self) -> None:
        """Build BM25 index from all per-control chunks."""
        collection = self._store.get_collection(COLLECTION_PER_CONTROL)
        if collection.count() == 0:
            logger.warning("Per-control collection is empty; BM25 index not built")
            return

        # Fetch all documents
        result = collection.get(include=["documents", "metadatas"])
        self._bm25_corpus = []
        tokenized = []
        for i, doc_id in enumerate(result["ids"]):
            doc_text = result["documents"][i]
            meta = result["metadatas"][i] if result["metadatas"] else {}
            self._bm25_corpus.append({
                "chunk_id": doc_id,
                "text": doc_text,
                "metadata": meta,
            })
            tokenized.append(doc_text.lower().split())

        if tokenized:
            self._bm25_index = BM25Okapi(tokenized)
            logger.info("BM25 index built with %d documents", len(tokenized))

    def retrieve(
        self,
        query: str,
        top_k: int = 10,
        dense_k: int = 15,
        bm25_k: int = 15,
    ) -> list[dict]:
        """
        Hybrid retrieval: BM25 + dense search across all collections + reranking.

        Returns top_k results after reranking.
        """
        candidates: dict[str, dict] = {}  # chunk_id → result

        # ── Dense search across all three collections ──
        for col_name in [COLLECTION_PER_CONTROL, COLLECTION_PER_LAYER, COLLECTION_PER_ATTACK]:
            hits = self._store.query(col_name, query, n_results=dense_k)
            for hit in hits:
                cid = hit["chunk_id"]
                if cid not in candidates or hit["distance"] < candidates[cid].get("distance", 999):
                    candidates[cid] = hit

        # ── BM25 sparse search ──
        if self._bm25_index and self._bm25_corpus:
            tokenized_query = query.lower().split()
            scores = self._bm25_index.get_scores(tokenized_query)
            top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:bm25_k]
            for idx in top_indices:
                if scores[idx] > 0:
                    doc = self._bm25_corpus[idx]
                    cid = doc["chunk_id"]
                    if cid not in candidates:
                        candidates[cid] = {
                            "chunk_id": cid,
                            "text": doc["text"],
                            "metadata": doc["metadata"],
                            "distance": 1.0,  # placeholder
                        }

        if not candidates:
            logger.warning("No candidates found for query: %s", query[:100])
            return []

        # ── Rerank with cross-encoder ──
        candidate_list = list(candidates.values())
        reranker = _get_reranker()
        pairs = [(query, c["text"][:512]) for c in candidate_list]  # truncate for reranker
        rerank_scores = reranker.predict(pairs)

        for i, c in enumerate(candidate_list):
            c["rerank_score"] = float(rerank_scores[i])

        # Sort by rerank score (higher is better)
        candidate_list.sort(key=lambda c: c["rerank_score"], reverse=True)

        results = candidate_list[:top_k]
        logger.info(
            "Hybrid retrieval: %d candidates → %d after reranking (query: %s...)",
            len(candidate_list), len(results), query[:60],
        )
        return results
