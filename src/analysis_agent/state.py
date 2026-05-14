import operator
from typing import Annotated, Any, Optional
from typing_extensions import TypedDict


class BuildParameter(TypedDict):
    name: str
    type: str          # string | boolean | choice | text
    default: str
    choices: list[str] # for choice type
    description: str
    source: str        # where it was found: makefile | source_code | readme | cmake


class BuildInfo(TypedDict):
    tool: str                    # CMake | Make | MSBuild | Gradle | Maven | Cargo | go | shell
    tool_path: str               # e.g. MSBuild.exe, /usr/bin/make
    commands: list[str]          # ordered build command sequence
    environment: str             # windows | linux | cross
    parameters: list[BuildParameter]
    notes: str


class ArtifactInfo(TypedDict):
    filename: str
    output_path: str
    artifact_type: str   # exe | dll | lib | so | elf | jar | dotnet_exe | dotnet_dll | wasm | other
    description: str


class AnalysisState(TypedDict):
    # --- inputs ---
    repo_path: str
    project_id: str
    vocabulary_context: str      # pre-formatted tactics/techniques for LLM prompt

    # --- file_explorer outputs ---
    file_tree: list[str]         # relative paths, depth-limited
    key_files: dict[str, str]    # {"role": "path"}, e.g. {"cmake": "CMakeLists.txt"}
    readme_content: str

    # --- parallel node outputs ---
    language_composition: dict[str, float]   # {"C++": 0.65, "C": 0.20, ...}
    build_info: Optional[BuildInfo]
    artifacts: list[ArtifactInfo]
    mitre_tactics: list[str]                 # tactic IDs: ["TA0002", "TA0005"]
    mitre_techniques: list[str]              # technique IDs: ["T1055", ...]
    custom_tags: list[str]                   # from custom vocabulary

    # --- bookkeeping ---
    completed_nodes: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]

    # --- final result ---
    result: Optional[dict[str, Any]]
