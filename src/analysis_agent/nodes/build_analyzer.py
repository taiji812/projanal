"""BuildAnalyzer node — uses LLM to extract build tool, commands, env, and parameters."""
import json
import re
from typing import Any

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import find_files_by_extension, grep_content, read_file

_MACRO_PATTERN = re.compile(
    r"""(?:
        \-D([A-Z_][A-Z0-9_]*)          # gcc/clang -DFOO
        |/D([A-Z_][A-Z0-9_]*)          # MSVC /DFOO
        |\$\(([A-Z_][A-Z0-9_]*)\)      # Makefile $(VAR)
        |ifdef\s+([A-Z_][A-Z0-9_]*)    # C preprocessor ifdef
        |if\s+defined\(([A-Z_][A-Z0-9_]*)\)  # #if defined(FOO)
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
    tool: str = Field(description="Primary build tool: CMake | Make | MSBuild | Gradle | Maven | Cargo | go | shell | unknown")
    tool_path: str = Field(default="", description="Executable path if specific, e.g. MSBuild.exe")
    commands: list[str] = Field(description="Ordered list of build commands to compile the project")
    environment: str = Field(description="Build OS: windows | linux | cross | unknown")
    parameters: list[_BuildParameter] = Field(default_factory=list)
    notes: str = Field(default="", description="Any additional observations about the build process")


def _collect_build_context(repo_path: str, key_files: dict[str, str]) -> str:
    """Gather relevant build files and macro hints into a single context string."""
    sections: list[str] = []

    # Read identified build files
    priority_roles = ["cmake", "cmake_presets", "makefile", "gradle", "maven",
                      "cargo", "gomod", "meson", "npm", "vs_solution", "vs_vcxproj",
                      "vs_csproj", "build_doc", "readme", "jenkinsfile"]
    for role in priority_roles:
        if role in key_files:
            content = read_file(repo_path, key_files[role], max_bytes=6144)
            if content:
                sections.append(f"=== {key_files[role]} ===\n{content}")

    # Detect shell/batch build scripts
    script_files = find_files_by_extension(repo_path, [".sh", ".bat", ".cmd", ".ps1"])
    for sf in script_files[:5]:
        content = read_file(repo_path, sf, max_bytes=2048)
        if content and any(kw in content.lower() for kw in ["cmake", "make", "msbuild", "gcc", "g++", "cl ", "build"]):
            sections.append(f"=== {sf} ===\n{content}")

    # Grep macro defines from C/C++/C# sources
    macro_hits = grep_content(
        repo_path,
        r"#\s*(?:ifdef|if\s+defined)\s*\(?\s*([A-Z_][A-Z0-9_]*)",
        extensions=[".c", ".cpp", ".h", ".hpp", ".cs"],
        max_matches=30,
    )
    if macro_hits:
        macro_lines = "\n".join(f"  {h['file']}:{h['line']}: {h['text']}" for h in macro_hits)
        sections.append(f"=== Preprocessor Macros (conditional compilation) ===\n{macro_lines}")

    # Grep -D flags in CMakeLists or scripts
    define_hits = grep_content(
        repo_path,
        r'(?:-D|-DCMAKE_)[A-Z_][A-Z0-9_]*',
        extensions=[".cmake", ".txt", ".sh", ".bat", ".cmd"],
        max_matches=20,
    )
    if define_hits:
        define_lines = "\n".join(f"  {h['file']}:{h['line']}: {h['text']}" for h in define_hits)
        sections.append(f"=== Compile Definitions (-D flags) ===\n{define_lines}")

    return "\n\n".join(sections)


_SYSTEM_PROMPT = """You are a build system expert. Analyze the provided build files and source code snippets.
Extract the following information and return it as valid JSON matching the schema.

Schema:
{
  "tool": "<CMake|Make|MSBuild|Gradle|Maven|Cargo|go|shell|unknown>",
  "tool_path": "<executable path or empty string>",
  "commands": ["<step1>", "<step2>", ...],
  "environment": "<windows|linux|cross|unknown>",
  "parameters": [
    {
      "name": "<PARAM_NAME>",
      "type": "<string|boolean|choice|text>",
      "default": "<default value or empty>",
      "choices": [],
      "description": "<what it controls>",
      "source": "<where found: cmake|makefile|source_code|readme>"
    }
  ],
  "notes": "<any important build notes>"
}

Rules:
- commands: provide the exact shell commands needed to build (e.g. "mkdir build && cd build && cmake .. && make")
- parameters: include only build-time variables that a user would pass (e.g. CMAKE_BUILD_TYPE, target platform macros)
- environment: infer from MSVC/MSBuild/bat → windows; gcc/make/sh → linux; if both exist → cross
- Return ONLY valid JSON, no markdown fences, no extra text."""


def build_analyzer_node(state: AnalysisState) -> dict:
    repo_path = state["repo_path"]
    key_files = state.get("key_files", {})

    context = _collect_build_context(repo_path, key_files)
    if not context.strip():
        return {
            "build_info": None,
            "completed_nodes": ["build_analyzer"],
            "errors": [],
        }

    llm = ChatOllama(model="gpt-oss:20b", temperature=0, format="json")

    messages = [
        ("system", _SYSTEM_PROMPT),
        ("human", f"Build context:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
        data: dict[str, Any] = json.loads(raw)
        build_info = _BuildInfoOutput(**data).model_dump()
    except Exception as e:
        return {
            "build_info": None,
            "completed_nodes": ["build_analyzer"],
            "errors": [f"build_analyzer: {e}"],
        }

    return {
        "build_info": build_info,
        "completed_nodes": ["build_analyzer"],
        "errors": [],
    }
