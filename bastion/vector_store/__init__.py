"""BASTION FAISS vector store for RAG similarity search."""

from bastion.vector_store.embeddings import get_text_embedding, EMBEDDING_DIM
from bastion.vector_store.faiss_client import build_index, search_index

__all__ = [
    "get_text_embedding",
    "EMBEDDING_DIM",
    "build_index",
    "search_index",
]
