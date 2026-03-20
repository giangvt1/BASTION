"""BASTION Pinecone vector store for RAG similarity search."""

from bastion.vector_store.embeddings import EMBEDDING_DIM, get_text_embedding
from bastion.vector_store.pinecone_client import query_vectors, upsert_vectors

__all__ = [
    "get_text_embedding",
    "EMBEDDING_DIM",
    "upsert_vectors",
    "query_vectors",
]
