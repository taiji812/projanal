"""AgentRunner — shared entry point for both CLI and REST API."""
import os
from pathlib import Path

from analysis_agent.graph import analysis_graph
from analysis_agent.state import AnalysisState
from analysis_agent.vocabulary.loader import format_vocabulary_context, load_vocabulary


def run_analysis(
    repo_path: str,
    project_id: str = "",
    custom_vocabulary_path: str | None = None,
) -> tuple[dict, dict]:
    """
    Run the full analysis pipeline synchronously.

    Args:
        repo_path: Absolute or relative path to the extracted project directory.
        project_id: Optional identifier (e.g. from upstream service).
        custom_vocabulary_path: Optional path to a custom vocabulary YAML file.

    Returns:
        Tuple of (result, reasoning) where:
          result   — ModuleProperty dict (the final JSON output)
          reasoning — dict with build_reasoning, artifact_reasoning, tactic_reasoning
    """
    repo_path = str(Path(repo_path).resolve())
    if not os.path.isdir(repo_path):
        raise ValueError(f"repo_path does not exist or is not a directory: {repo_path}")

    vocab = load_vocabulary(custom_vocabulary_path)
    vocabulary_context = format_vocabulary_context(vocab)

    initial_state: AnalysisState = {
        "repo_path": repo_path,
        "project_id": project_id or Path(repo_path).name,
        "vocabulary_context": vocabulary_context,
        # outputs — will be populated by nodes
        "file_tree": [],
        "key_files": {},
        "readme_content": "",
        "language_composition": {},
        "source_language": [],
        "build_features": None,
        "execution_features": None,
        "payload_info": None,
        "module_category": "",
        "capabilities": [],
        "post_exploits": [],
        "mitre_tactics": [],
        "mitre_techniques": [],
        "custom_tags": [],
        "build_reasoning": "",
        "artifact_reasoning": "",
        "tactic_reasoning": "",
        "completed_nodes": [],
        "errors": [],
        "result": None,
    }

    final_state = analysis_graph.invoke(initial_state)

    result = final_state.get("result") or {}
    reasoning = {
        "build_reasoning":    final_state.get("build_reasoning", ""),
        "artifact_reasoning": final_state.get("artifact_reasoning", ""),
        "tactic_reasoning":   final_state.get("tactic_reasoning", ""),
    }
    return result, reasoning
