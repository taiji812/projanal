"""Aggregator node — assembles parallel node outputs into ModuleProperty JSON."""
from analysis_agent.schema import (
    BuildEnv,
    BuildFeatures,
    BuildParam,
    ExecutionComponent,
    ExecutionFeatures,
    FunctionalFeatures,
    ModuleForm,
    ModuleProperty,
    PayloadInfo,
)
from analysis_agent.state import AnalysisState


def aggregator_node(state: AnalysisState) -> dict:
    errors = state.get("errors", [])

    # Build ModuleProperty, validating each nested section with Pydantic
    try:
        build_features = (
            BuildFeatures.model_validate(state["build_features"])
            if state.get("build_features")
            else BuildFeatures()
        )
    except Exception as e:
        errors = list(errors) + [f"aggregator: build_features validation failed: {e}"]
        build_features = BuildFeatures()

    try:
        execution_features = (
            ExecutionFeatures.model_validate(state["execution_features"])
            if state.get("execution_features")
            else ExecutionFeatures()
        )
    except Exception as e:
        errors = list(errors) + [f"aggregator: execution_features validation failed: {e}"]
        execution_features = ExecutionFeatures()

    try:
        payload_info = (
            PayloadInfo.model_validate(state["payload_info"])
            if state.get("payload_info")
            else None
        )
    except Exception as e:
        errors = list(errors) + [f"aggregator: payload_info validation failed: {e}"]
        payload_info = None

    prop = ModuleProperty(
        module_name=state.get("project_id", ""),
        module_category=state.get("module_category", ""),
        module_form=ModuleForm(
            form_type="sourcecode",
            source_language=state.get("source_language", []),
            has_submodule=False,
        ),
        functional_features=FunctionalFeatures(
            capabilities=state.get("capabilities", []),
            post_exploits=state.get("post_exploits", []),
        ),
        build_features=build_features,
        execution_features=execution_features,
        payload_info=payload_info,
        mitre_tactics=state.get("mitre_tactics", []),
        mitre_techniques=state.get("mitre_techniques", []),
        errors=errors,
    )

    return {"result": prop.model_dump(), "completed_nodes": ["aggregator"]}
