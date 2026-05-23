"""ArtifactAnalyzer node — infers execution components and optional payload info.

Context source (in priority order):
  1. RAG retrieval from ChromaDB
  2. Fallback: direct file reads
"""

import json
import os
from typing import Any, Optional

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field, model_validator

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import find_files_by_extension, read_file


# ---------------------------------------------------------------------------
# Pydantic models matching ExecutionFeatures / PayloadInfo schema
# ---------------------------------------------------------------------------

class _ExecutionComponent(BaseModel):
    name: str
    exec_arch: list[str] = Field(default_factory=list)
    exec_os: list[str] = Field(default_factory=list)
    exec_type: list[str] = Field(default_factory=list)
    exec_dependency: list[str] = Field(default_factory=list)
    multi_instance: bool = False
    pathname: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: dict) -> dict:
        # Accept common LLM field variants
        if not data.get("pathname") and data.get("filename"):
            data["pathname"] = data["filename"]
        if not data.get("exec_type") and data.get("artifact_type"):
            data["exec_type"] = [data["artifact_type"]]
        if not data.get("exec_os"):
            data["exec_os"] = ["windows"]
        if not data.get("exec_arch"):
            data["exec_arch"] = ["x86", "x64"]
        return data


class _ExecutionFeaturesOutput(BaseModel):
    components: list[_ExecutionComponent] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _unwrap(cls, data: dict) -> dict:
        if isinstance(data, list):
            return {"components": data}
        for key in ("artifacts", "items", "outputs"):
            if key in data and "components" not in data:
                data["components"] = data[key]
        return data


class _KeyInfo(BaseModel):
    size: Optional[int] = None
    key_input_type: Optional[str] = None


class _PayloadTransformInfo(BaseModel):
    algorithm: Optional[str] = None
    keyinfo: Optional[_KeyInfo] = None


class _PayloadInfoOutput(BaseModel):
    payload_exec_type: list[str] = Field(default_factory=list)
    execution_method: list[str] = Field(default_factory=list)
    execution_technique_notes: list[str] = Field(default_factory=list)
    payload_target_path: Optional[str] = None
    delivery_type: Optional[str] = None
    payload_transform_info: Optional[_PayloadTransformInfo] = None
    embedding_type: Optional[str] = None


class _ArtifactAnalysisOutput(BaseModel):
    execution_features: _ExecutionFeaturesOutput = Field(
        default_factory=_ExecutionFeaturesOutput
    )
    payload_info: Optional[_PayloadInfoOutput] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: dict) -> dict:
        # LLM may return flat {components: [...]} without the execution_features wrapper
        if "components" in data and "execution_features" not in data:
            data["execution_features"] = {"components": data.pop("components")}
        return data


# ---------------------------------------------------------------------------
# RAG retrieval
# ---------------------------------------------------------------------------

_ARTIFACT_QUERIES = [
    "executable binary output assembly name filename",
    "OutputPath OutputType AssemblyName WinExe Library dotnet",
    "add_executable add_library install cmake target",
    "jar war artifact maven gradle package",
    "cargo bin lib rust output",
    "payload loader inject reflective CLR shellcode",
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

_SYSTEM_PROMPT = """You are a build system expert. Identify execution components and payload info.

Return JSON:
{
  "execution_features": {
    "components": [
      {
        "name": "<component name, e.g. Server, Client, Loader DLL>",
        "exec_arch": ["x86", "x64"],
        "exec_os": ["windows"],
        "exec_type": ["<exe(.net)|dll(.net)|exe(native)|dll(native)|exe(script)|zip|other>"],
        "exec_dependency": [],
        "multi_instance": false,
        "pathname": "<output filename>"
      }
    ]
  },
  "payload_info": null
}

For Loader / Injector type tools, populate payload_info instead of null:
{
  "payload_exec_type": ["<exe(.net)|dll(native)|shellcode|...>"],
  "execution_method": ["<reflective-loading|process-injection|CLR-loading|shellcode-exec|...>"],
  "execution_technique_notes": ["<technique description>"],
  "payload_target_path": "<path where payload is placed or null>",
  "delivery_type": "<external-file|embedded|download>",
  "payload_transform_info": {
    "algorithm": "<RC4|AES|XOR|null>",
    "keyinfo": {"size": 128, "key_input_type": "<user-input|embedded>"}
  },
  "embedding_type": null
}

Rules:
- exec_type format: "exe(.net)", "dll(.net)", "exe(native)", "dll(native)"
  MSBuild WinExe/.csproj → exe(.net); Library/.csproj → dll(.net)
  .vcxproj DLL → dll(native); .vcxproj EXE → exe(native)
- exec_arch: infer from Platform property; default ["x86","x64"] if AnyCPU or unknown
- multi_instance: true if multiple instances can run simultaneously (e.g. RAT client)
- payload_info: only for Loader/Injector; null for RAT, Implant, standalone tools
- Return ONLY valid JSON, no markdown fences.

/no_think"""


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

def artifact_analyzer_node(state: AnalysisState) -> dict:
    repo_path  = state["repo_path"]
    project_id = state["project_id"]
    key_files  = state.get("key_files", {})

    context = _rag_context(project_id) or _fallback_context(repo_path, key_files)

    if not context.strip():
        return {
            "execution_features": None,
            "payload_info": None,
            "completed_nodes": ["artifact_analyzer"],
            "errors": [],
        }

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
        ("human", f"Build configuration:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
        if not raw:
            raise ValueError("LLM returned empty response")
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:]).rstrip("`").strip()
        data: dict[str, Any] = json.loads(raw)
        output = _ArtifactAnalysisOutput(**data)
        execution_features = output.execution_features.model_dump()
        payload_info = output.payload_info.model_dump() if output.payload_info else None
    except Exception as e:
        return {
            "execution_features": None,
            "payload_info": None,
            "completed_nodes": ["artifact_analyzer"],
            "errors": [f"artifact_analyzer: {e}"],
        }

    return {
        "execution_features": execution_features,
        "payload_info": payload_info,
        "completed_nodes": ["artifact_analyzer"],
        "errors": [],
    }
