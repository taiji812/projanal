"""BuildAnalyzer node — extracts build tool, commands, environment, and parameters.

Context source (in priority order):
  1. RAG retrieval from ChromaDB (populated by index_builder)
  2. Fallback: direct file reads (old behaviour, used if index not available)
"""

import json
import os
import re
from typing import Any

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import find_files_by_extension, grep_content, read_file

_MACRO_PATTERN = re.compile(
    r"""(?:
        \-D([A-Z_][A-Z0-9_]*)
        |/D([A-Z_][A-Z0-9_]*)
        |\$\(([A-Z_][A-Z0-9_]*)\)
        |ifdef\s+([A-Z_][A-Z0-9_]*)
        |if\s+defined\(([A-Z_][A-Z0-9_]*)\)
    )""",
    re.VERBOSE | re.IGNORECASE,
)


class _BuildParameter(BaseModel):
    name: str
    type: str = Field(default="string", description="string | boolean | choice | text")
    default: str = Field(default="")
    choices: list[str] = Field(default_factory=list)
    description: str = Field(default="")
    source: str = Field(default="")


class _BuildInfoOutput(BaseModel):
    tool: str = Field(description="CMake | Make | MSBuild | Gradle | Maven | Cargo | go | shell | docker | unknown")
    tool_path: str = Field(default="")
    commands: list[str] = Field(description="Ordered build commands")
    environment: str = Field(description="windows | linux | cross | unknown")
    parameters: list[_BuildParameter] = Field(default_factory=list)
    notes: str = Field(default="")


# ---------------------------------------------------------------------------
# RAG retrieval (primary path)
# ---------------------------------------------------------------------------

_BUILD_QUERIES = [
    "build tool cmake msbuild makefile gradle maven cargo docker",
    "compile command executable output binary script",
    "build configuration debug release platform architecture",
    "build parameter macro define variable argument flag",
    "OutputPath AssemblyName OutputType add_executable target_link_libraries",
]


def _rag_context(project_id: str) -> str:
    from analysis_agent.indexer.store import get_project_collection, retrieve_multi
    col = get_project_collection(project_id)
    if col is None or col.count() == 0:
        return ""
    return retrieve_multi(project_id, _BUILD_QUERIES, n_per_query=5)


# ---------------------------------------------------------------------------
# Fallback: direct file reads (used when index not available)
# ---------------------------------------------------------------------------

def _fallback_context(repo_path: str, key_files: dict[str, str]) -> str:
    sections: list[str] = []
    priority_roles = [
        "cmake", "cmake_presets", "makefile", "gradle", "maven",
        "cargo", "gomod", "meson", "npm", "vs_vcxproj",
        "vs_csproj", "build_doc", "readme", "jenkinsfile",
    ]
    for role in priority_roles:
        if role in key_files:
            content = read_file(repo_path, key_files[role], max_bytes=3072)
            if content:
                sections.append(f"=== {key_files[role]} ===\n{content}")

    # Shell/batch scripts containing build keywords
    for sf in find_files_by_extension(repo_path, [".sh", ".bat", ".cmd", ".ps1"])[:5]:
        content = read_file(repo_path, sf, max_bytes=2048)
        if content and any(kw in content.lower() for kw in ["cmake", "make", "msbuild", "gcc", "build"]):
            sections.append(f"=== {sf} ===\n{content}")

    # Preprocessor macros
    macro_hits = grep_content(
        repo_path,
        r"#\s*(?:ifdef|if\s+defined)\s*\(?\s*([A-Z_][A-Z0-9_]*)",
        extensions=[".c", ".cpp", ".h", ".hpp", ".cs"],
        max_matches=20,
    )
    if macro_hits:
        lines = "\n".join(f"  {h['file']}:{h['line']}: {h['text']}" for h in macro_hits)
        sections.append(f"=== Preprocessor Macros ===\n{lines}")

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a build system expert. Analyze the provided build context and return JSON:
{
  "tool": "<CMake|Make|MSBuild|Gradle|Maven|Cargo|go|shell|docker|unknown>",
  "tool_path": "<executable path or empty>",
  "commands": ["<step1>", "<step2>"],
  "environment": "<windows|linux|cross|unknown>",
  "parameters": [
    {
      "name": "<PARAM>",
      "type": "<string|boolean|choice|text>",
      "default": "<value>",
      "choices": [],
      "description": "<what it controls>",
      "source": "<cmake|makefile|source_code|readme|csproj>"
    }
  ],
  "notes": "<additional build notes>"
}

Rules:
- commands: exact shell commands needed to build the project
- parameters: only build-time variables a user would pass (e.g. CMAKE_BUILD_TYPE, Configuration)
- environment: MSVC/MSBuild/bat → windows; gcc/make/sh → linux; both → cross
- Return ONLY valid JSON, no markdown fences.

/no_think"""


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

def build_analyzer_node(state: AnalysisState) -> dict:
    repo_path  = state["repo_path"]
    project_id = state["project_id"]
    key_files  = state.get("key_files", {})

    context = _rag_context(project_id) or _fallback_context(repo_path, key_files)

    if not context.strip():
        return {"build_info": None, "completed_nodes": ["build_analyzer"], "errors": []}

    llm = ChatOllama(
        model=os.getenv("OLLAMA_MODEL", "gpt-oss:20b"),
        temperature=0,
        format="json",
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        num_predict=4096,
        num_ctx=8192,
    )
    messages = [
        ("system", _SYSTEM_PROMPT),
        ("human", f"Build context:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
        if not raw:
            raise ValueError("LLM returned empty response")
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:]).rstrip("`").strip()
        data: dict[str, Any] = json.loads(raw)
        build_info = _BuildInfoOutput(**data).model_dump()
    except Exception as e:
        return {"build_info": None, "completed_nodes": ["build_analyzer"], "errors": [f"build_analyzer: {e}"]}

    return {"build_info": build_info, "completed_nodes": ["build_analyzer"], "errors": []}
