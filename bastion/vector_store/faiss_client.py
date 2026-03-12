"""
FAISS index wrapper -- build, save, load, and search.

Supports two deployment modes:
1. **Pre-built index** (production): Load index.faiss + labels.json from
   local file or S3 (Lambda downloads to /tmp on cold start).
2. **Runtime build** (development): Build index from embeddings in memory.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import faiss
import numpy as np

from bastion.logger import get_logger

logger = get_logger(__name__)


def build_index(embeddings: np.ndarray) -> faiss.Index:
    """Build a flat L2 FAISS index from an (N, D) embedding matrix."""
    if embeddings.ndim != 2:
        raise ValueError(f"Expected 2-D array, got shape {embeddings.shape}")

    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(embeddings.astype(np.float32))
    logger.info("faiss.index_built", vectors=index.ntotal, dim=dim)
    return index


def save_index(
    index: faiss.Index,
    labels: list[str],
    directory: str | Path,
    name: str = "index",
) -> None:
    """Persist a FAISS index + labels to disk.

    Creates ``<name>.faiss`` and ``<name>.labels.json`` in *directory*.
    Use this offline to pre-build indices and upload to S3.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    index_path = directory / f"{name}.faiss"
    labels_path = directory / f"{name}.labels.json"

    faiss.write_index(index, str(index_path))
    labels_path.write_text(json.dumps(labels), encoding="utf-8")

    logger.info(
        "faiss.index_saved",
        path=str(index_path),
        vectors=index.ntotal,
        labels=len(labels),
    )


def load_index(
    directory: str | Path,
    name: str = "index",
) -> tuple[faiss.Index, list[str]] | None:
    """Load a pre-built FAISS index + labels from disk.

    Returns ``(index, labels)`` or ``None`` if the files don't exist.
    """
    directory = Path(directory)
    index_path = directory / f"{name}.faiss"
    labels_path = directory / f"{name}.labels.json"

    if not index_path.exists():
        return None

    index = faiss.read_index(str(index_path))
    labels: list[str] = []
    if labels_path.exists():
        labels = json.loads(labels_path.read_text(encoding="utf-8"))

    logger.info(
        "faiss.index_loaded",
        path=str(index_path),
        vectors=index.ntotal,
        labels=len(labels),
    )
    return index, labels


def load_index_from_s3(
    bucket: str,
    s3_prefix: str,
    name: str = "index",
    local_dir: str = "/tmp/faiss_cache",
) -> tuple[faiss.Index, list[str]] | None:
    """Download a pre-built FAISS index from S3, cache in *local_dir*.

    Checks local cache first to avoid re-downloading on Lambda warm starts.
    Returns ``(index, labels)`` or ``None`` if the S3 objects don't exist.
    """
    local = Path(local_dir)
    cached = load_index(local, name)
    if cached is not None:
        logger.info("faiss.s3_cache_hit", name=name)
        return cached

    try:
        from bastion.tools.aws_helpers import get_boto3_client

        s3 = get_boto3_client("s3")
        local.mkdir(parents=True, exist_ok=True)

        index_key = f"{s3_prefix}/{name}.faiss"
        labels_key = f"{s3_prefix}/{name}.labels.json"

        s3.download_file(bucket, index_key, str(local / f"{name}.faiss"))
        logger.info("faiss.s3_downloaded", key=index_key)

        try:
            s3.download_file(bucket, labels_key, str(local / f"{name}.labels.json"))
        except Exception:
            logger.info("faiss.s3_no_labels_file", key=labels_key)

        return load_index(local, name)

    except Exception:
        logger.warning("faiss.s3_load_failed", bucket=bucket, prefix=s3_prefix)
        return None


def search_index(
    index: faiss.Index,
    query_vector: np.ndarray,
    k: int = 5,
    labels: list[str] | None = None,
) -> list[dict]:
    """Search the index for the *k* nearest neighbours of *query_vector*.

    Returns a list of dicts with ``id``, ``distance``, and ``label``
    (when *labels* is provided).
    """
    if query_vector.ndim == 1:
        query_vector = query_vector.reshape(1, -1)

    query_vector = query_vector.astype(np.float32)
    distances, indices = index.search(query_vector, k)

    results: list[dict] = []
    for rank in range(k):
        idx = int(indices[0][rank])
        if idx == -1:
            continue
        entry: dict[str, Any] = {"id": idx, "distance": float(distances[0][rank])}
        if labels and 0 <= idx < len(labels):
            entry["label"] = labels[idx]
        results.append(entry)

    return results
