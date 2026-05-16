"""IndexBuilder node — parses source files with tree-sitter, embeds chunks, stores in ChromaDB.

Runs sequentially after file_explorer, before the parallel analysis nodes.
All analysis nodes retrieve context from the vector store instead of reading raw files.
"""

from pathlib import Path

from analysis_agent.indexer.chunker import chunk_file
from analysis_agent.indexer.store import create_project_collection
from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import read_file

_INDEXABLE_EXTS = {
    # Source
    ".cs", ".cpp", ".c", ".h", ".hpp",
    ".go", ".rs", ".java", ".py",
    ".js", ".mjs", ".ts",
    ".sh", ".ps1", ".bat", ".cmd",
    # Build / config
    ".csproj", ".vcxproj", ".props",
    ".sln",
    ".cmake",
    ".mk",
    ".toml",   # Cargo.toml
    ".mod",    # go.mod
    ".gradle",
    ".xml",    # pom.xml, etc.
}

_INDEXABLE_NAMES = {
    "makefile", "gnumakefile", "cmakelists.txt",
    "cargo.toml", "go.mod", "jenkinsfile",
    "readme.md", "readme.txt", "readme",
    "building.md", "build.md", "install.md",
}

# Hard cap: index at most this many files per project
_MAX_FILES = 400
# Hard cap per file (bytes) — avoids ingesting huge generated files
_MAX_FILE_BYTES = 65_536  # 64 KB


def _is_indexable(rel: str) -> bool:
    p = Path(rel)
    return (
        p.suffix.lower() in _INDEXABLE_EXTS
        or p.name.lower() in _INDEXABLE_NAMES
    )


def index_builder_node(state: AnalysisState) -> dict:
    repo_path   = state["repo_path"]
    project_id  = state["project_id"]
    file_tree   = state.get("file_tree", [])
    key_files   = state.get("key_files", {})

    priority_paths = set(key_files.values())

    # Select and order files: priority (build/key) files first
    candidates = [f for f in file_tree if _is_indexable(f)]
    ordered = [f for f in candidates if f in priority_paths]
    ordered += [f for f in candidates if f not in priority_paths]
    ordered = ordered[:_MAX_FILES]

    try:
        collection = create_project_collection(project_id)
    except Exception as e:
        return {
            "completed_nodes": ["index_builder"],
            "errors": [f"index_builder: collection creation failed: {e}"],
        }

    all_chunks = []
    for rel_path in ordered:
        content = read_file(repo_path, rel_path, max_bytes=_MAX_FILE_BYTES)
        if not content.strip():
            continue
        try:
            chunks = chunk_file(rel_path, content)
            all_chunks.extend(chunks)
        except Exception:
            continue

    errors: list[str] = []

    if not all_chunks:
        return {"completed_nodes": ["index_builder"], "errors": errors}

    # Batch-insert into ChromaDB (handles duplicate IDs by skipping)
    _BATCH = 100
    for i in range(0, len(all_chunks), _BATCH):
        batch = all_chunks[i : i + _BATCH]
        # Deduplicate IDs within the batch
        seen_ids: set[str] = set()
        deduped = []
        for c in batch:
            if c.id not in seen_ids:
                seen_ids.add(c.id)
                deduped.append(c)
        try:
            collection.add(
                ids=[c.id for c in deduped],
                documents=[c.content for c in deduped],
                metadatas=[{
                    "file_path":   c.file_path,
                    "chunk_type":  c.chunk_type,
                    "language":    c.language,
                    "tags":        ",".join(c.tags),
                    "start_line":  c.start_line,
                } for c in deduped],
            )
        except Exception as e:
            errors.append(f"index_builder batch {i}: {e}")

    return {
        "completed_nodes": ["index_builder"],
        "errors": errors,
    }
