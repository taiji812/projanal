"""ArtifactAnalyzer node — infers build output artifacts.

Context source (in priority order):
  1. RAG retrieval from ChromaDB
  2. Fallback: direct file reads
"""

import json
import os

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field, model_validator

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import find_files_by_extension, read_file

_ARTIFACT_TYPES = (
    "exe", "dll", "lib", "so", "elf",
    "jar", "war", "ear",
    "dotnet_exe", "dotnet_dll",
    "wasm",
    "shared_library", "static_library",
    "python_wheel", "npm_package",
    "docker_image", "container_image",
    "other",
)


# ---------------------------------------------------------------------------
# Pydantic models with field-name normalization
# ---------------------------------------------------------------------------

class _ArtifactOutput(BaseModel):
    filename: str = Field(description="Output filename including extension")
    output_path: str = Field(default="", description="Relative output directory")
    artifact_type: str = Field(description=f"One of: {', '.join(_ARTIFACT_TYPES)}")
    description: str = Field(default="", description="One sentence description")

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: dict) -> dict:
        """Remap common LLM field-name variants to canonical names."""
        aliases = {
            "filename":      ["name", "file_name", "output_file", "file"],
            "output_path":   ["path", "output_dir", "directory", "location", "output_location"],
            "artifact_type": ["type", "kind", "artifact_kind"],
        }
        for canonical, alts in aliases.items():
            if not data.get(canonical):
                for alt in alts:
                    if data.get(alt):
                        data[canonical] = data[alt]
                        break
        return data


class _ArtifactsOutput(BaseModel):
    artifacts: list[_ArtifactOutput]

    @model_validator(mode="before")
    @classmethod
    def _unwrap(cls, data: dict) -> dict:
        if isinstance(data, list):
            return {"artifacts": data}
        for key in ("items", "outputs", "results", "builds"):
            if key in data and "artifacts" not in data:
                data["artifacts"] = data[key]
        return data


# ---------------------------------------------------------------------------
# RAG retrieval (primary path)
# ---------------------------------------------------------------------------

_ARTIFACT_QUERIES = [
    "executable binary output assembly name filename",
    "OutputPath OutputType AssemblyName WinExe Library dotnet",
    "add_executable add_library install cmake target",
    "jar war artifact maven gradle package",
    "cargo bin lib rust output",
    "docker image container build push",
]


def _rag_context(project_id: str) -> str:
    from analysis_agent.indexer.store import get_project_collection, retrieve_multi
    col = get_project_collection(project_id)
    if col is None or col.count() == 0:
        return ""
    return retrieve_multi(project_id, _ARTIFACT_QUERIES, n_per_query=4)


# ---------------------------------------------------------------------------
# Fallback: direct file reads
# ---------------------------------------------------------------------------

def _fallback_context(repo_path: str, key_files: dict[str, str]) -> str:
    sections: list[str] = []
    roles = [
        "cmake", "vs_vcxproj", "vs_csproj", "vs_solution",
        "gradle", "maven", "cargo", "gomod", "makefile",
        "dockerfile", "jenkinsfile",
    ]
    for role in roles:
        if role in key_files:
            content = read_file(repo_path, key_files[role], max_bytes=4096)
            if content:
                sections.append(f"=== {key_files[role]} ===\n{content}")
    for df in find_files_by_extension(repo_path, [".dockerfile"]):
        content = read_file(repo_path, df, max_bytes=2048)
        if content:
            sections.append(f"=== {df} ===\n{content}")
    if "readme" in key_files:
        content = read_file(repo_path, key_files["readme"], max_bytes=2048)
        if content:
            sections.append(f"=== {key_files['readme']} ===\n{content}")
    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = f"""You are a build system expert. List only the actual build artifacts from the config.

Return JSON:
{{
  "artifacts": [
    {{
      "filename": "<AssemblyName+ext or target name>",
      "output_path": "<OutputPath value, or empty string if unknown>",
      "artifact_type": "<one of: {', '.join(_ARTIFACT_TYPES)}>",
      "description": "<one sentence>"
    }}
  ]
}}

Rules:
- MSBuild/.csproj: filename = AssemblyName + ext based on OutputType (WinExe→dotnet_exe, Library→dotnet_dll)
- CMake: filename from add_executable()/add_library() target name
- Rust/Cargo: from [[bin]] name or package name
- output_path: use exact OutputPath value; empty string if not found
- List Debug and Release as SEPARATE artifacts only if OutputPath differs
- Do NOT invent filenames not found in the config
- Return ONLY valid JSON, no markdown fences."""


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

def artifact_analyzer_node(state: AnalysisState) -> dict:
    repo_path  = state["repo_path"]
    project_id = state["project_id"]
    key_files  = state.get("key_files", {})

    context = _rag_context(project_id) or _fallback_context(repo_path, key_files)

    if not context.strip():
        return {"artifacts": [], "completed_nodes": ["artifact_analyzer"], "errors": []}

    llm = ChatOllama(
        model="gpt-oss:20b",
        temperature=0,
        format="json",
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        num_predict=4096,
        num_ctx=32768,
    )
    messages = [
        ("system", _SYSTEM_PROMPT),
        ("human", f"Build configuration:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
        if not raw:
            raise ValueError("LLM returned empty response")
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:]).rstrip("`").strip()
        data = json.loads(raw)
        output = _ArtifactsOutput(**data)
        artifacts = [a.model_dump() for a in output.artifacts]
    except Exception as e:
        return {"artifacts": [], "completed_nodes": ["artifact_analyzer"], "errors": [f"artifact_analyzer: {e}"]}

    return {"artifacts": artifacts, "completed_nodes": ["artifact_analyzer"], "errors": []}
