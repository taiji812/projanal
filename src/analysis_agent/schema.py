"""Pydantic output schema — ModuleProperty.

This is the canonical output format produced by the analysis agent.
All node outputs are assembled into this model by the aggregator.
"""
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class ModuleForm(BaseModel):
    form_type: str = "sourcecode"       # sourcecode | binary | hybrid
    source_language: list[str] = Field(default_factory=list)
    has_submodule: bool = False


class FunctionalFeatures(BaseModel):
    capabilities: list[str] = Field(default_factory=list)
    post_exploits: list[str] = Field(default_factory=list)
    notes: Optional[str] = None


class BuildParam(BaseModel):
    param_type: str = "string"                  # string | text | choice | object
    param_title: str = ""
    param_name: str
    param_description: str = ""
    param_schema: Optional[str] = None          # JSON Schema string (object type only)
    serialization_type: Optional[str] = None    # json | xml (object type only)
    param_default: Optional[str] = None
    choice_list: Optional[list[str]] = None     # choice type only


class ContainerInfo(BaseModel):
    image_name: str = ""
    image_version: str = ""


class BuildEnv(BaseModel):
    build_env_os: str = "windows"               # windows | linux | macos
    container_info: Optional[ContainerInfo] = None


class BuildFeatures(BaseModel):
    build_tool: str = "msbuild"                 # msbuild | msbuild_dotnet | jenkinsfile | python | golang
    no_concurrent_build: bool = False
    build_tool_args: str = ""                   # args string; ${VAR} for variable params
    build_params: list[BuildParam] = Field(default_factory=list)
    build_env: BuildEnv = Field(default_factory=BuildEnv)
    artifacts_archive: str = ""                 # glob pattern for output artifacts
    artifacts_archive_zip: bool = False
    artifacts_archive_zipname: Optional[str] = None
    build_dependencies: list[str] = Field(default_factory=list)


class ExecutionComponent(BaseModel):
    name: str
    exec_arch: list[str] = Field(default_factory=list)      # x86 | x64 | arm | etc.
    exec_os: list[str] = Field(default_factory=list)        # windows | linux | macos
    exec_type: list[str] = Field(default_factory=list)      # exe(.net) | dll(native) | shellcode | ...
    exec_dependency: list[str] = Field(default_factory=list)
    multi_instance: bool = False
    pathname: Optional[str] = None


class ExecutionFeatures(BaseModel):
    components: list[ExecutionComponent] = Field(default_factory=list)


class KeyInfo(BaseModel):
    size: Optional[int] = None
    key_input_type: Optional[str] = None        # fixed | user-input | file


class PayloadTransformInfo(BaseModel):
    algorithm: Optional[str] = None             # RC4 | AES | XOR | ...
    keyinfo: Optional[KeyInfo] = None


class PayloadInfo(BaseModel):
    payload_exec_type: list[str] = Field(default_factory=list)
    execution_method: list[str] = Field(default_factory=list)
    execution_technique_notes: list[str] = Field(default_factory=list)
    payload_target_path: Optional[str] = None
    delivery_type: Optional[str] = None         # embedded | download | external-file
    payload_transform_info: Optional[PayloadTransformInfo] = None
    embedding_type: Optional[str] = None        # resource | overlay | data | text


class ModuleProperty(BaseModel):
    module_name: str
    module_category: str = ""                   # RAT | C2Framework | Loader | Library | Builder
    module_form: ModuleForm = Field(default_factory=ModuleForm)
    functional_features: FunctionalFeatures = Field(default_factory=FunctionalFeatures)
    build_features: BuildFeatures = Field(default_factory=BuildFeatures)
    execution_features: ExecutionFeatures = Field(default_factory=ExecutionFeatures)
    payload_info: Optional[PayloadInfo] = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    errors: list[str] = Field(default_factory=list)
