import operator
from typing import Annotated, Any, Optional
from typing_extensions import TypedDict


class AnalysisState(TypedDict):
    # --- inputs ---
    repo_path: str
    project_id: str
    vocabulary_context: str      # pre-formatted tactics/techniques for LLM prompt

    # --- file_explorer outputs ---
    file_tree: list[str]         # relative paths, depth-limited
    key_files: dict[str, str]    # {"role": "path"}
    readme_content: str

    # --- parallel node outputs ---
    language_composition: dict[str, float]   # {"C++": 0.65, ...} internal use
    source_language: list[str]               # ["C#", "C/C++"] for module_form
    build_features: Optional[dict]           # BuildFeatures-compatible dict
    execution_features: Optional[dict]       # ExecutionFeatures-compatible dict
    payload_info: Optional[dict]             # PayloadInfo-compatible dict (loaders only)
    module_category: str                     # RAT | Loader | Implant | ...
    capabilities: list[str]                  # high-level capability groups
    post_exploits: list[str]                 # specific post-exploit features
    mitre_tactics: list[str]                 # tactic IDs: ["TA0002", "TA0005"]
    mitre_techniques: list[str]              # technique IDs: ["T1055", ...]
    custom_tags: list[str]                   # from custom vocabulary

    # --- reasoning (human-readable derivation notes) ---
    build_reasoning: str
    artifact_reasoning: str
    tactic_reasoning: str

    # --- bookkeeping ---
    completed_nodes: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]

    # --- final result ---
    result: Optional[dict[str, Any]]
