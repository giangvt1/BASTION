"""
Pinecone vector store wrapper for BASTION.

Handles initialization, upserting, and querying the Pinecone index.
Uses namespaces to separate corpora (phishing, mitre) within a single index.

Two deployment modes:
1. **Cloud index** (production): Data already in Pinecone, just query.
2. **Auto-populate** (development): Upsert from local CSV on first access.
"""

from __future__ import annotations

from typing import Any

from pinecone import Pinecone, ServerlessSpec

from bastion.config import config
from bastion.logger import get_logger

logger = get_logger(__name__)

_pc: Pinecone | None = None
_index = None


def _get_client() -> Pinecone:
    """Return a cached Pinecone client instance."""
    global _pc
    if _pc is None:
        _pc = Pinecone(api_key=config.pinecone_api_key)
        logger.info("pinecone.client_init")
    return _pc


def get_index():
    """Return the cached Pinecone Index handle.

    Creates the index with serverless spec if it doesn't exist yet.
    """
    global _index
    if _index is not None:
        return _index

    pc = _get_client()
    index_name = config.pinecone_index_name

    existing = [idx.name for idx in pc.list_indexes()]
    if index_name not in existing:
        logger.info("pinecone.creating_index", name=index_name, dimension=config.pinecone_dimension)
        pc.create_index(
            name=index_name,
            dimension=config.pinecone_dimension,
            metric="cosine",
            spec=ServerlessSpec(
                cloud=config.pinecone_cloud,
                region=config.pinecone_region,
            ),
        )

    _index = pc.Index(index_name)
    logger.info("pinecone.index_connected", name=index_name)
    return _index


def namespace_count(namespace: str) -> int:
    """Return the vector count for a given namespace (0 if empty/missing)."""
    try:
        idx = get_index()
        stats = idx.describe_index_stats()
        ns_stats = stats.get("namespaces", {})
        return ns_stats.get(namespace, {}).get("vector_count", 0)
    except Exception:
        logger.warning("pinecone.stats_failed", namespace=namespace)
        return 0


def upsert_vectors(
    namespace: str,
    ids: list[str],
    vectors: list[list[float]],
    metadata_list: list[dict[str, Any]],
    batch_size: int = 100,
) -> int:
    """Batch-upsert vectors into a Pinecone namespace.

    Args:
        namespace: Pinecone namespace (e.g. "phishing", "mitre").
        ids: Vector IDs (must be unique within the namespace).
        vectors: List of embedding vectors (each a list of floats).
        metadata_list: Metadata dicts to store alongside each vector.
        batch_size: Upsert batch size (Pinecone recommends <= 100).

    Returns:
        Total number of vectors upserted.
    """
    idx = get_index()
    records = list(zip(ids, vectors, metadata_list))

    for i in range(0, len(records), batch_size):
        batch = records[i : i + batch_size]
        idx.upsert(vectors=batch, namespace=namespace)

    logger.info("pinecone.upserted", namespace=namespace, count=len(records))
    return len(records)


def query_vectors(
    namespace: str,
    query_vector: list[float],
    k: int = 5,
) -> list[dict[str, Any]]:
    """Query the Pinecone index for the top-k most similar vectors.

    Args:
        namespace: Pinecone namespace to search in.
        query_vector: The query embedding vector.
        k: Number of results to return.

    Returns:
        List of dicts with keys: id, score, label, text.
    """
    idx = get_index()

    results = idx.query(
        vector=query_vector,
        top_k=k,
        namespace=namespace,
        include_metadata=True,
    )

    formatted: list[dict[str, Any]] = []
    for match in results.get("matches", []):
        meta = match.get("metadata", {})
        formatted.append({
            "id": match["id"],
            "score": float(match["score"]),
            "label": meta.get("label", ""),
            "text": meta.get("text", ""),
        })

    logger.info("pinecone.query", namespace=namespace, results=len(formatted))
    return formatted
