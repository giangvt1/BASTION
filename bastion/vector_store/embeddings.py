"""
Deterministic embedding generation.

Uses SHA-256 hash chaining to produce fixed-dimension vectors without
requiring an external model download. Produces stable, comparable
embeddings suitable for FAISS nearest-neighbour search.
"""

from __future__ import annotations

import hashlib

import numpy as np

EMBEDDING_DIM = 128


def _hash_to_floats(text: str, dim: int) -> list[float]:
    """Turn *text* into *dim* floats via repeated SHA-256 hashing."""
    floats: list[float] = []
    seed = text.encode("utf-8")

    while len(floats) < dim:
        digest = hashlib.sha256(seed).digest()
        for b in digest:
            floats.append((b / 127.5) - 1.0)
        seed = digest

    return floats[:dim]


def get_text_embedding(text: str) -> list[float]:
    """Produce a deterministic L2-normalised 128-dim embedding for *text*."""
    raw = np.array(_hash_to_floats(text, EMBEDDING_DIM), dtype=np.float32)

    norm = np.linalg.norm(raw)
    if norm > 0:
        raw = raw / norm

    return raw.tolist()


def get_email_embedding(subject: str, body: str) -> list[float]:
    """Produce an embedding from email subject + body."""
    combined = f"{subject or ''} {body or ''}"
    return get_text_embedding(combined)
