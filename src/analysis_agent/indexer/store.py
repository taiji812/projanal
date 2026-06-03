"""ChromaDB in-memory vector store — one ephemeral collection per project.

The client and collections live at module level (process-scoped).
All LangGraph nodes in the same process share this registry by project_id.

Embedding backend (in priority order):
  1. ANALYSIS_EMBED_MODEL env var → Ollama embedding model
  2. Default → chromadb DefaultEmbeddingFunction (downloads all-MiniLM-L6-v2 ~90 MB on first run)
"""

import os
import re
from typing import Optional

import chromadb
from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

# Module-level singletons
_client: Optional[chromadb.ClientAPI] = None
_collections: dict[str, chromadb.Collection] = {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_client() -> chromadb.ClientAPI:
    global _client
    if _client is None:
        _client = chromadb.EphemeralClient()
    return _client


def _safe_name(project_id: str) -> str:
    """ChromaDB collection name: alphanumeric + underscore, max 63 chars."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", project_id)
    return f"p_{safe}"[:63]


def _make_embedding_function():
    model = os.getenv("ANALYSIS_EMBED_MODEL", "").strip()
    if model:
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
        return OllamaEmbeddingFunction(
            model_name=model,
            url=f"{base_url}/api/embeddings",
        )

    # Default: sentence-transformers/all-MiniLM-L6-v2 (auto-downloaded)
    return DefaultEmbeddingFunction()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_project_collection(project_id: str) -> chromadb.Collection:
    """Drop-and-recreate a fresh in-memory collection for the project."""
    client = _get_client()
    name = _safe_name(project_id)

    try:
        client.delete_collection(name)
    except Exception:
        pass

    ef = _make_embedding_function()
    collection = client.get_or_create_collection(name, embedding_function=ef)
    _collections[project_id] = collection
    return collection


def get_project_collection(project_id: str) -> Optional[chromadb.Collection]:
    return _collections.get(project_id)


def retrieve(project_id: str, query: str, n_results: int = 8) -> str:
    """Single-query retrieval → formatted context string."""
    collection = get_project_collection(project_id)
    if collection is None:
        return ""

    count = collection.count()
    if count == 0:
        return ""

    results = collection.query(
        query_texts=[query],
        n_results=min(n_results, count),
    )

    parts: list[str] = []
    seen: set[str] = set()
    for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
        key = doc[:80]
        if key in seen:
            continue
        seen.add(key)
        parts.append(f"--- {meta.get('file_path', '?')} [L{meta.get('start_line', '?')}] ---\n{doc}")

    return "\n\n".join(parts)


def retrieve_multi(
    project_id: str,
    queries: list[str],
    n_per_query: int = 4,
    max_chars: int = 5000,
) -> str:
    """Multi-query retrieval with deduplication and character-level cap."""
    collection = get_project_collection(project_id)
    if collection is None:
        return ""

    count = collection.count()
    if count == 0:
        return ""

    n = min(n_per_query, count)
    seen: dict[str, str] = {}  # content_key → formatted string

    for query in queries:
        results = collection.query(query_texts=[query], n_results=n)
        for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
            key = doc[:80]
            if key not in seen:
                seen[key] = f"--- {meta.get('file_path', '?')} [L{meta.get('start_line', '?')}] ---\n{doc}"

    # Enforce character budget (most relevant chunks first)
    parts: list[str] = []
    total = 0
    for chunk_str in seen.values():
        if total + len(chunk_str) > max_chars:
            break
        parts.append(chunk_str)
        total += len(chunk_str)

    return "\n\n".join(parts)
