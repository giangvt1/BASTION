"""
Semantic embedding generation for vector search.

Provides two embedding strategies:
1. Deterministic hash-based (legacy, fast, no dependencies)
2. Semantic BERT-based (new, high quality, requires sentence-transformers)

The semantic embedder is used by default when available, with automatic
fallback to hash-based embeddings if the ML model fails to load.
"""

from __future__ import annotations

import hashlib
import os

import numpy as np

from bastion.logger import get_logger

logger = get_logger(__name__)

# Feature flag for semantic embeddings
USE_SEMANTIC_EMBEDDINGS = os.getenv("BASTION_USE_SEMANTIC_EMBEDDINGS", "true").lower() == "true"

# Embedding dimensions
HASH_EMBEDDING_DIM = 128
SEMANTIC_EMBEDDING_DIM = 384


def _hash_to_floats(text: str, dim: int) -> list[float]:
    """Turn *text* into *dim* floats via repeated SHA-256 hashing.
    
    Legacy deterministic embedding method. Fast but does not capture
    semantic similarity.
    """
    floats: list[float] = []
    seed = text.encode("utf-8")

    while len(floats) < dim:
        digest = hashlib.sha256(seed).digest()
        for b in digest:
            floats.append((b / 127.5) - 1.0)
        seed = digest

    return floats[:dim]


def _get_hash_embedding(text: str) -> list[float]:
    """Produce a deterministic L2-normalised 128-dim hash embedding."""
    raw = np.array(_hash_to_floats(text, HASH_EMBEDDING_DIM), dtype=np.float32)

    norm = np.linalg.norm(raw)
    if norm > 0:
        raw = raw / norm

    return raw.tolist()


def _get_semantic_embedding(text: str) -> list[float]:
    """Produce a semantic 384-dim BERT embedding using sentence-transformers."""
    try:
        from bastion.models.ml_models import get_semantic_embedder
        
        embedder = get_semantic_embedder()
        return embedder.get_text_embedding(text)
    except Exception:
        logger.warning(
            "embeddings.semantic_fallback",
            message="Semantic embedder failed, falling back to hash embeddings",
            exc_info=True,
        )
        # Fallback to hash embeddings, but pad to 384 dims for Pinecone compatibility
        hash_emb = _get_hash_embedding(text)
        # Pad with zeros to match semantic dimension
        return hash_emb + [0.0] * (SEMANTIC_EMBEDDING_DIM - HASH_EMBEDDING_DIM)


def get_text_embedding(text: str) -> list[float]:
    """Produce an embedding for text.
    
    Uses semantic BERT embeddings by default (384-dim), with automatic
    fallback to hash embeddings if ML model is unavailable.
    
    Args:
        text: Input text to embed
    
    Returns:
        384-dimensional embedding vector (or 128-dim if semantic disabled)
    """
    if USE_SEMANTIC_EMBEDDINGS:
        return _get_semantic_embedding(text)
    else:
        return _get_hash_embedding(text)


def get_email_embedding(subject: str, body: str) -> list[float]:
    """Produce an embedding from email subject + body.
    
    Args:
        subject: Email subject line
        body: Email body text
    
    Returns:
        384-dimensional embedding vector (or 128-dim if semantic disabled)
    """
    combined = f"{subject or ''} {body or ''}"
    
    if USE_SEMANTIC_EMBEDDINGS:
        try:
            from bastion.models.ml_models import get_semantic_embedder
            
            embedder = get_semantic_embedder()
            return embedder.get_email_embedding(subject, body)
        except Exception:
            logger.warning(
                "embeddings.email_semantic_fallback",
                exc_info=True,
            )
            # Fallback to hash
            hash_emb = _get_hash_embedding(combined)
            return hash_emb + [0.0] * (SEMANTIC_EMBEDDING_DIM - HASH_EMBEDDING_DIM)
    else:
        return _get_hash_embedding(combined)
