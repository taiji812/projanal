"""BuildAnalyzer node — extracts build tool, args, parameters, and artifact glob.

Context source (in priority order):
  1. RAG retrieval from ChromaDB (populated by index_builder)
  2. Fallback: direct file reads
"""

import json
import os
import re
from typing import Any, Optional

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field, model_validator

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import find_files_by_extension, grep_content, read_file


# ---------------------------------------------------------------------------
# Pydantic models matching BuildFeatures schema
# ---------------------------------------------------------------------------

class _BuildParam(BaseModel):
    param_type: str = Field(default="string")   # string | choice | object | boolean
    param_title: str = Field(default="")
    param_name: str
    param_description: str = Field(default="")
    param_default: Optional[str] = Field(default=None)
    choice_list: Optional[list[str]] = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: dict) -> dict:
        # Accept old field names from LLM
        if not data.get("param_name") and data.get("name"):
            data["param_name"] = data["name"]
        if not data.get("param_title") and data.get("param_name"):
            data["param_title"] = data.get("param_name", "")
        if not data.get("param_default") and data.get("default"):
            data["param_default"] = str(data["default"])
        if not data.get("choice_list") and data.get("choices"):
            data["choice_list"] = data["choices"]
        if not data.get("param_type") and data.get("type"):
            data["param_type"] = data["type"]
        return data


class _BuildFeaturesOutput(BaseModel):
    build_tool: str = Field(default="unknown")
    no_concurrent_build: bool = Field(default=False)
    build_tool_args: str = Field(default="")
    build_params: list[_BuildParam] = Field(default_factory=list)
    build_env: dict = Field(default_factory=lambda: {"build_env_os": "unknown"})
    artifacts_archive: str = Field(default="")
    build_dependencies: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: dict) -> dict:
        # Accept old field names
        if not data.get("build_tool") and data.get("tool"):
            data["build_tool"] = data["tool"]
        if not data.get("build_tool_args") and data.get("commands"):
            cmds = data["commands"]
            if isinstance(cmds, list) and cmds:
                # Strip leading tool name, keep args
                first = cmds[0]
                for prefix in ("msbuild ", "cmake ", "make ", "cargo ", "go "):
                    if first.lower().startswith(prefix):
                        first = first[len(prefix):]
                        break
                data["build_tool_args"] = first
        if not data.get("build_env"):
            env = data.get("environment", "unknown")
            data["build_env"] = {"build_env_os": env}
        if not data.get("build_params") and data.get("parameters"):
            data["build_params"] = data["parameters"]
        return data


# ---------------------------------------------------------------------------
# RAG retrieval
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
# Fallback: direct file reads
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

    for sf in find_files_by_extension(repo_path, [".sh", ".bat", ".cmd", ".ps1"])[:5]:
        content = read_file(repo_path, sf, max_bytes=2048)
        if content and any(kw in content.lower() for kw in ["cmake", "make", "msbuild", "gcc", "build"]):
            sections.append(f"=== {sf} ===\n{content}")

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

_SYSTEM_PROMPT = """You are a build system expert. Analyze the build configuration and return JSON.

{
  "build_tool": "<msbuild_dotnet|msbuild|cmake|make|go|cargo|gradle|maven|shell|docker|unknown>",
  "no_concurrent_build": false,
  "build_tool_args": "<solution/project file + fixed args; use ${PARAM_NAME} for variable params>",
  "build_params": [
    {
      "param_type": "<string|choice|boolean|object>",
      "param_title": "<human readable label>",
      "param_name": "<PARAM_NAME>",
      "param_description": "<what it controls>",
      "param_default": "<default value or null>",
      "choice_list": ["Release", "Debug"]
    }
  ],
  "build_env": {"build_env_os": "<windows|linux|macos|cross>"},
  "artifacts_archive": "<glob pattern for output artifacts, e.g. Outputs/* or bin\\\\Release\\\\*.exe>",
  "build_dependencies": [],
  "reasoning": "<Explain: (1) which file(s)/patterns identified the build tool, (2) how build_tool_args was derived and which properties are fixed vs variable, (3) how each build_param was found and what it controls, (4) what evidence led to the artifacts_archive glob. Reference specific file names and property values.>"
}

Rules:
- build_tool: use "msbuild_dotnet" for .NET/.csproj; "msbuild" for native .vcxproj
- build_tool_args: start from solution/project file, NOT the tool name itself
  Fixed params go inline (/p:Configuration=Release); variable params use ${PARAM_NAME}
  Example: "MyProject.sln /p:Configuration=Release /p:Platform=${platform}"
- param_type "choice" when values are enumerable; "string" otherwise
- artifacts_archive: single glob covering all built outputs (e.g. "bin/Release/*.exe")
  Use "**/*.exe" or "Outputs/*" style — prefer shortest covering glob
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
        return {"build_features": None, "completed_nodes": ["build_analyzer"], "errors": []}

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
        reasoning = data.pop("reasoning", "")
        build_features = _BuildFeaturesOutput(**data).model_dump()
    except Exception as e:
        return {
            "build_features": None,
            "build_reasoning": "",
            "completed_nodes": ["build_analyzer"],
            "errors": [f"build_analyzer: {e}"],
        }

    return {
        "build_features": build_features,
        "build_reasoning": reasoning,
        "completed_nodes": ["build_analyzer"],
        "errors": [],
    }
