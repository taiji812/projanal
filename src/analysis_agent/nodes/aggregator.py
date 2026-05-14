"""Aggregator node — combines parallel node outputs into the final JSON result."""
from datetime import datetime, timezone

from analysis_agent.state import AnalysisState


def aggregator_node(state: AnalysisState) -> dict:
    result = {
        "project_id": state.get("project_id", ""),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "language_composition": state.get("language_composition", {}),
        "mitre_tactics": state.get("mitre_tactics", []),
        "mitre_techniques": state.get("mitre_techniques", []),
        "custom_tags": state.get("custom_tags", []),
        "build_info": state.get("build_info"),
        "artifacts": state.get("artifacts", []),
        "errors": state.get("errors", []),
    }
    return {"result": result, "completed_nodes": ["aggregator"]}
