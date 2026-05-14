"""ArtifactAnalyzer node — uses LLM to infer build output artifacts."""
import json

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import read_file

# artifact_type vocabulary
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


class _ArtifactOutput(BaseModel):
    filename: str = Field(description="Output filename including extension, e.g. agent.exe")
    output_path: str = Field(description="Relative directory where artifact is produced, e.g. build/Release/")
    artifact_type: str = Field(description=f"One of: {', '.join(_ARTIFACT_TYPES)}")
    description: str = Field(description="One sentence describing what this artifact is/does")


class _ArtifactsOutput(BaseModel):
    artifacts: list[_ArtifactOutput]


_SYSTEM_PROMPT = f"""You are a build system expert. Given build configuration files, infer all build artifacts produced.

For each artifact return JSON matching:
{{
  "artifacts": [
    {{
      "filename": "<output filename with extension>",
      "output_path": "<relative output directory>",
      "artifact_type": "<one of: {', '.join(_ARTIFACT_TYPES)}>",
      "description": "<one sentence>"
    }}
  ]
}}

Rules:
- Include ALL distinct output binaries/libraries (debug and release variants count as separate if paths differ)
- For CMake: look for add_executable(), add_library(), install() directives
- For MSBuild/VS: look for OutputType, AssemblyName, OutputPath in .vcxproj/.csproj
- For Maven/Gradle: look for artifactId, jar/war/aar packaging
- For Go: infer from package main and go.mod module name
- For Rust: look at Cargo.toml [[bin]] and [lib] sections
- artifact_type: use 'exe' for Windows executable, 'elf' for Linux executable,
  'dll' for Windows DLL, 'so' for Linux shared lib, 'dotnet_exe'/'dotnet_dll' for .NET
- Return ONLY valid JSON, no markdown fences, no extra text."""


def _collect_artifact_context(repo_path: str, key_files: dict[str, str]) -> str:
    from analysis_agent.tools.filesystem import find_files_by_extension
    sections: list[str] = []
    roles = ["cmake", "vs_vcxproj", "vs_csproj", "vs_solution",
             "gradle", "maven", "cargo", "gomod", "makefile",
             "dockerfile", "jenkinsfile"]
    for role in roles:
        if role in key_files:
            content = read_file(repo_path, key_files[role], max_bytes=4096)
            if content:
                sections.append(f"=== {key_files[role]} ===\n{content}")
    # Dockerfiles not named exactly "Dockerfile"
    for df in find_files_by_extension(repo_path, [".dockerfile"]):
        content = read_file(repo_path, df, max_bytes=2048)
        if content:
            sections.append(f"=== {df} ===\n{content}")
    if "readme" in key_files:
        content = read_file(repo_path, key_files["readme"], max_bytes=2048)
        if content:
            sections.append(f"=== {key_files['readme']} ===\n{content}")
    return "\n\n".join(sections)


def artifact_analyzer_node(state: AnalysisState) -> dict:
    repo_path = state["repo_path"]
    key_files = state.get("key_files", {})

    context = _collect_artifact_context(repo_path, key_files)
    if not context.strip():
        return {
            "artifacts": [],
            "completed_nodes": ["artifact_analyzer"],
            "errors": [],
        }

    llm = ChatOllama(model="gpt-oss:20b", temperature=0, format="json")

    messages = [
        ("system", _SYSTEM_PROMPT),
        ("human", f"Build configuration:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
        data = json.loads(raw)
        output = _ArtifactsOutput(**data)
        artifacts = [a.model_dump() for a in output.artifacts]
    except Exception as e:
        return {
            "artifacts": [],
            "completed_nodes": ["artifact_analyzer"],
            "errors": [f"artifact_analyzer: {e}"],
        }

    return {
        "artifacts": artifacts,
        "completed_nodes": ["artifact_analyzer"],
        "errors": [],
    }
