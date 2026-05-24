"""Unit tests for the vocabulary normalization logic added in the schema redesign.

Covers:
  - tactic_classifier: _derive_category, _derive_capabilities, _derive_post_exploits
  - language_analyzer: _normalize_to_sourcecode_vocab, _derive_source_language
  - build_analyzer:    _BuildParam normalizer, _BuildFeaturesOutput normalizer
  - artifact_analyzer: _PayloadInfoOutput vocab normalizer
"""

import sys
import types

# ---------------------------------------------------------------------------
# Stub heavy runtime deps so all four modules can be imported without a full
# langchain / ollama / chromadb installation.
# ---------------------------------------------------------------------------

def _stub(name: str, **attrs):
    mod = sys.modules.get(name) or types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod


_stub("langchain_ollama", ChatOllama=type("ChatOllama", (), {}))
_stub("analysis_agent.state",   AnalysisState=dict)
_stub("analysis_agent.tools")
_stub("analysis_agent.tools.filesystem",
      grep_content=lambda *a, **kw: [],
      read_file=lambda *a, **kw: "",
      find_files_by_extension=lambda *a, **kw: [],
      count_lines_by_extension=lambda *a, **kw: {})
_stub("analysis_agent.indexer")
_stub("analysis_agent.indexer.store",
      get_project_collection=lambda *a, **kw: None,
      retrieve_multi=lambda *a, **kw: "")

import pytest

from analysis_agent.nodes.tactic_classifier import (
    _derive_category,
    _derive_capabilities,
    _derive_post_exploits,
    _VALID_CAPABILITIES,
    _VALID_POST_EXPLOITS,
    _VALID_MODULE_CATEGORIES,
)
from analysis_agent.nodes.language_analyzer import (
    _normalize_to_sourcecode_vocab,
    _derive_source_language,
)
from analysis_agent.nodes.build_analyzer import (
    _BuildParam,
    _BuildFeaturesOutput,
    _BUILD_TOOL_NORMALIZE,
    _PARAM_TYPE_NORMALIZE,
)
from analysis_agent.nodes.artifact_analyzer import (
    _PayloadInfoOutput,
    _VALID_EXECUTION_METHODS,
    _VALID_EMBEDDING_TYPES,
    _VALID_KEY_INPUT_TYPES,
)


# ===========================================================================
# tactic_classifier — _derive_category
# ===========================================================================

class TestDeriveCategory:
    def test_c2_framework_tag_maps_to_c2framework(self):
        assert _derive_category(["C2 Framework"], "") == "C2Framework"

    def test_loader_tag_maps_to_loader(self):
        assert _derive_category(["Loader"], "") == "Loader"

    def test_injector_tag_maps_to_loader(self):
        assert _derive_category(["Injector"], "") == "Loader"

    def test_dropper_tag_maps_to_loader(self):
        assert _derive_category(["Dropper"], "") == "Loader"

    def test_implant_tag_maps_to_rat(self):
        assert _derive_category(["Implant"], "") == "RAT"

    def test_keylogger_tag_maps_to_rat(self):
        assert _derive_category(["Keylogger"], "") == "RAT"

    def test_ransomware_tag_maps_to_rat(self):
        assert _derive_category(["Ransomware"], "") == "RAT"

    def test_llm_c2_framework_string_normalizes(self):
        assert _derive_category([], "C2 Framework") == "C2Framework"

    def test_llm_implant_normalizes_to_rat(self):
        assert _derive_category([], "Implant") == "RAT"

    def test_llm_injector_normalizes_to_loader(self):
        assert _derive_category([], "Injector") == "Loader"

    def test_llm_valid_rat_passthrough(self):
        assert _derive_category([], "RAT") == "RAT"

    def test_llm_valid_library_passthrough(self):
        assert _derive_category([], "Library") == "Library"

    def test_llm_valid_builder_passthrough(self):
        assert _derive_category([], "Builder") == "Builder"

    def test_unknown_llm_category_defaults_to_rat(self):
        assert _derive_category([], "SomeWeirdThing") == "RAT"

    def test_tag_takes_priority_over_llm(self):
        # Tag says Loader, LLM says RAT — tag wins
        assert _derive_category(["Loader"], "RAT") == "Loader"

    def test_output_always_in_valid_set(self):
        for tag in ["C2 Framework", "Implant", "Loader", "Injector",
                    "Dropper", "Keylogger", "Ransomware", "Rootkit"]:
            result = _derive_category([tag], "")
            assert result in _VALID_MODULE_CATEGORIES, f"tag {tag!r} → {result!r}"

        for llm_cat in ["RAT", "C2Framework", "Loader", "Library", "Builder",
                        "Implant", "Backdoor", "Injector", "Unknown"]:
            result = _derive_category([], llm_cat)
            assert result in _VALID_MODULE_CATEGORIES, f"llm {llm_cat!r} → {result!r}"


# ===========================================================================
# tactic_classifier — _derive_capabilities
# ===========================================================================

class TestDeriveCapabilities:
    def test_valid_llm_caps_pass_through(self):
        caps = _derive_capabilities([], ["command and control", "execution"])
        assert "command and control" in caps
        assert "execution" in caps

    def test_invalid_llm_cap_is_filtered(self):
        caps = _derive_capabilities([], ["command and control", "not-a-real-cap"])
        assert "not-a-real-cap" not in caps
        assert "command and control" in caps

    def test_tag_appends_cap(self):
        caps = _derive_capabilities(["Loader"], [])
        assert "execution" in caps
        assert "defense evasion" in caps

    def test_no_duplicates_from_tag_and_llm(self):
        caps = _derive_capabilities(["Loader"], ["execution"])
        assert caps.count("execution") == 1

    def test_all_outputs_in_valid_vocab(self):
        caps = _derive_capabilities(
            ["C2 Framework", "Keylogger", "Loader"],
            ["execution", "exfiltration", "bad-value"],
        )
        for c in caps:
            assert c in _VALID_CAPABILITIES

    def test_empty_inputs_return_empty(self):
        assert _derive_capabilities([], []) == []


# ===========================================================================
# tactic_classifier — _derive_post_exploits
# ===========================================================================

class TestDerivePostExploits:
    def test_valid_llm_post_exploit_passes(self):
        pe = _derive_post_exploits([], ["keylogger"])
        assert "keylogger" in pe

    def test_credential_dump_normalizes(self):
        pe = _derive_post_exploits([], ["credential dump"])
        assert "credential and hash harvesting" in pe
        assert "credential dump" not in pe

    def test_network_scan_normalizes(self):
        pe = _derive_post_exploits([], ["network scan"])
        assert "network and host enumeration" in pe
        assert "network scan" not in pe

    def test_lateral_move_normalizes(self):
        pe = _derive_post_exploits([], ["lateral move"])
        assert "lateral movement" in pe

    def test_ransomware_typo_normalizes(self):
        pe = _derive_post_exploits([], ["ransomware"])
        assert "ransomeware" in pe   # service VO has typo "ransomeware"

    def test_invalid_value_is_filtered(self):
        pe = _derive_post_exploits([], ["not-a-real-feature", "screenshot"])
        assert "not-a-real-feature" not in pe
        assert "screenshot" in pe

    def test_tag_appends_post_exploit(self):
        pe = _derive_post_exploits(["Keylogger"], [])
        assert "keylogger" in pe

    def test_c2_tag_appends_command_and_control(self):
        pe = _derive_post_exploits(["C2 Framework"], [])
        assert "command and control" in pe

    def test_credential_harvester_tag(self):
        pe = _derive_post_exploits(["Credential Harvester"], [])
        assert "credential and hash harvesting" in pe

    def test_no_duplicates(self):
        pe = _derive_post_exploits(["Keylogger"], ["keylogger"])
        assert pe.count("keylogger") == 1

    def test_all_outputs_in_valid_vocab(self):
        pe = _derive_post_exploits(
            ["Keylogger", "C2 Framework", "Credential Harvester"],
            ["screenshot", "credential dump", "network scan", "garbage"],
        )
        for item in pe:
            assert item in _VALID_POST_EXPLOITS


# ===========================================================================
# language_analyzer — _normalize_to_sourcecode_vocab
# ===========================================================================

class TestNormalizeToSourcecodeVocab:
    def test_go_maps_to_golang(self):
        assert _normalize_to_sourcecode_vocab("Go") == "Golang"

    def test_javascript_already_correct(self):
        # The ext map now directly emits "Javascript"
        assert _normalize_to_sourcecode_vocab("Javascript") == "Javascript"

    def test_typescript_already_correct(self):
        assert _normalize_to_sourcecode_vocab("Typescript") == "Typescript"

    def test_known_langs_pass_through(self):
        for lang in ["C/C++", "C#", "Python", "Rust", "Java", "Assembly",
                     "Ruby", "Nim", "Perl", "PHP", "Golang"]:
            assert _normalize_to_sourcecode_vocab(lang) == lang

    def test_unknown_lang_maps_to_etc(self):
        assert _normalize_to_sourcecode_vocab("Kotlin") == "Etc."
        assert _normalize_to_sourcecode_vocab("Swift") == "Etc."
        assert _normalize_to_sourcecode_vocab("Lua") == "Etc."
        assert _normalize_to_sourcecode_vocab("Zig") == "Etc."


# ===========================================================================
# language_analyzer — _derive_source_language
# ===========================================================================

class TestDeriveSourceLanguage:
    def test_go_composition_yields_golang(self):
        result = _derive_source_language({"Go": 0.95, "YAML": 0.05})
        assert "Golang" in result
        assert "Go" not in result

    def test_csharp_passes_through(self):
        result = _derive_source_language({"C#": 0.80, "XML": 0.20})
        assert "C#" in result

    def test_config_langs_excluded(self):
        # XML, YAML, JSON should never appear in source_language
        result = _derive_source_language({"C#": 0.5, "XML": 0.3, "YAML": 0.2})
        assert "XML" not in result
        assert "YAML" not in result

    def test_other_ext_excluded(self):
        result = _derive_source_language({"C#": 0.6, "Other (.resx)": 0.4})
        assert "Other (.resx)" not in result

    def test_low_ratio_excluded(self):
        result = _derive_source_language({"C/C++": 0.98, "Perl": 0.01})
        assert "Perl" not in result

    def test_capped_at_three(self):
        result = _derive_source_language({
            "C/C++": 0.4, "C#": 0.3, "Python": 0.2, "Go": 0.1
        })
        assert len(result) <= 3

    def test_deduplication_after_normalization(self):
        # Go and Golang both map to "Golang" — should appear only once
        result = _derive_source_language({"Go": 0.5, "Golang": 0.4})
        assert result.count("Golang") == 1

    def test_unknown_lang_maps_to_etc(self):
        result = _derive_source_language({"Kotlin": 0.8, "XML": 0.2})
        assert "Etc." in result

    def test_etc_deduplication(self):
        # Multiple unknown langs should yield at most one "Etc."
        result = _derive_source_language({"Kotlin": 0.4, "Swift": 0.4, "YAML": 0.2})
        assert result.count("Etc.") <= 1

    def test_empty_composition(self):
        assert _derive_source_language({}) == []


# ===========================================================================
# build_analyzer — _BuildParam normalizer
# ===========================================================================

class TestBuildParamNormalizer:
    def test_boolean_param_type_normalizes_to_string(self):
        p = _BuildParam(param_name="debug", param_type="boolean", param_default="false")
        assert p.param_type == "string"

    def test_bool_param_type_normalizes_to_string(self):
        p = _BuildParam(param_name="flag", param_type="bool", param_default="true")
        assert p.param_type == "string"

    def test_enum_param_type_normalizes_to_choice(self):
        p = _BuildParam(param_name="platform", param_type="enum",
                        choice_list=["x86", "x64"])
        assert p.param_type == "choice"

    def test_multiline_param_type_normalizes_to_text(self):
        p = _BuildParam(param_name="note", param_type="multiline", param_default="")
        assert p.param_type == "text"

    def test_valid_string_type_unchanged(self):
        p = _BuildParam(param_name="version", param_type="string", param_default="1.0")
        assert p.param_type == "string"

    def test_valid_choice_type_unchanged(self):
        p = _BuildParam(param_name="cfg", param_type="choice",
                        choice_list=["Release", "Debug"])
        assert p.param_type == "choice"

    def test_valid_text_type_unchanged(self):
        p = _BuildParam(param_name="notes", param_type="text", param_default="")
        assert p.param_type == "text"

    def test_valid_object_type_unchanged(self):
        p = _BuildParam(param_name="config", param_type="object", param_default="{}")
        assert p.param_type == "object"

    def test_name_alias_accepted(self):
        # LLM sometimes returns "name" instead of "param_name"
        p = _BuildParam(**{"name": "platform", "param_type": "choice",
                           "choices": ["x86", "x64"]})
        assert p.param_name == "platform"
        assert p.choice_list == ["x86", "x64"]

    def test_choices_alias_accepted(self):
        p = _BuildParam(param_name="cfg", choices=["Release", "Debug"])
        assert p.choice_list == ["Release", "Debug"]

    def test_title_defaults_to_param_name(self):
        p = _BuildParam(param_name="platform", param_type="choice",
                        choice_list=["x86"])
        assert p.param_title == "platform"


# ===========================================================================
# build_analyzer — _BuildFeaturesOutput normalizer
# ===========================================================================

class TestBuildFeaturesOutputNormalizer:
    def test_msbuild_dotnet_passthrough(self):
        bf = _BuildFeaturesOutput(build_tool="msbuild_dotnet", build_tool_args="Foo.sln")
        assert bf.build_tool == "msbuild_dotnet"

    def test_go_normalizes_to_golang(self):
        bf = _BuildFeaturesOutput(build_tool="go", build_tool_args="build ./...")
        assert bf.build_tool == "golang"

    def test_cmake_normalizes_to_msbuild(self):
        bf = _BuildFeaturesOutput(build_tool="cmake", build_tool_args="-B build")
        assert bf.build_tool == "msbuild"

    def test_unknown_normalizes_to_msbuild(self):
        bf = _BuildFeaturesOutput(build_tool="unknown")
        assert bf.build_tool == "msbuild"

    def test_unsupported_tool_normalizes_to_msbuild(self):
        bf = _BuildFeaturesOutput(build_tool="gradle")
        assert bf.build_tool == "msbuild"

    def test_artifacts_archive_zip_field(self):
        bf = _BuildFeaturesOutput(
            build_tool="msbuild",
            artifacts_archive_zip=True,
            artifacts_archive_zipname="out.zip",
        )
        assert bf.artifacts_archive_zip is True
        assert bf.artifacts_archive_zipname == "out.zip"

    def test_artifacts_archive_zip_defaults_false(self):
        bf = _BuildFeaturesOutput(build_tool="msbuild")
        assert bf.artifacts_archive_zip is False
        assert bf.artifacts_archive_zipname is None

    def test_tool_alias_accepted(self):
        bf = _BuildFeaturesOutput(**{"tool": "msbuild_dotnet", "build_tool_args": "Foo.sln"})
        assert bf.build_tool == "msbuild_dotnet"

    def test_model_dump_includes_new_fields(self):
        bf = _BuildFeaturesOutput(
            build_tool="msbuild",
            artifacts_archive_zip=True,
            artifacts_archive_zipname="dist.zip",
        )
        d = bf.model_dump()
        assert "artifacts_archive_zip" in d
        assert "artifacts_archive_zipname" in d
        assert d["artifacts_archive_zip"] is True
        assert d["artifacts_archive_zipname"] == "dist.zip"


# ===========================================================================
# artifact_analyzer — _PayloadInfoOutput vocab normalizer
# ===========================================================================

class TestPayloadInfoOutputNormalizer:
    # --- embedding_type ---

    def test_valid_embedding_type_passthrough(self):
        p = _PayloadInfoOutput(embedding_type="resource")
        assert p.embedding_type == "resource"

    def test_clr_embedding_normalizes_to_resource(self):
        p = _PayloadInfoOutput(embedding_type="clr")
        assert p.embedding_type == "resource"

    def test_dll_embedding_normalizes_to_data(self):
        p = _PayloadInfoOutput(embedding_type="dll")
        assert p.embedding_type == "data"

    def test_invalid_embedding_type_becomes_none(self):
        p = _PayloadInfoOutput(embedding_type="not-valid")
        assert p.embedding_type is None

    # --- execution_method ---

    def test_valid_execution_method_passthrough(self):
        p = _PayloadInfoOutput(execution_method=["reflective-loading"])
        assert "reflective-loading" in p.execution_method

    def test_reflective_string_normalizes(self):
        p = _PayloadInfoOutput(execution_method=["reflective"])
        assert "reflective-loading" in p.execution_method

    def test_clr_loading_variant_normalizes(self):
        p = _PayloadInfoOutput(execution_method=["clr loading"])
        assert ".net-assembly-loading" in p.execution_method

    def test_process_hollowing_normalizes(self):
        p = _PayloadInfoOutput(execution_method=["process hollowing"])
        assert "process-hollowing" in p.execution_method

    def test_invalid_execution_method_filtered(self):
        p = _PayloadInfoOutput(execution_method=["some-made-up-method", "reflective-loading"])
        assert "some-made-up-method" not in p.execution_method
        assert "reflective-loading" in p.execution_method

    def test_execution_method_deduplication(self):
        p = _PayloadInfoOutput(execution_method=["reflective-loading", "reflective"])
        assert p.execution_method.count("reflective-loading") == 1

    def test_all_valid_execution_methods_pass(self):
        for m in _VALID_EXECUTION_METHODS:
            p = _PayloadInfoOutput(execution_method=[m])
            assert m in p.execution_method

    # --- key_input_type ---

    def test_fixed_key_input_type_passthrough(self):
        p = _PayloadInfoOutput(payload_transform_info={
            "algorithm": "RC4",
            "keyinfo": {"size": 16, "key_input_type": "fixed"},
        })
        assert p.payload_transform_info.keyinfo.key_input_type == "fixed"

    def test_embedded_key_input_normalizes_to_fixed(self):
        p = _PayloadInfoOutput(payload_transform_info={
            "algorithm": "RC4",
            "keyinfo": {"size": 16, "key_input_type": "embedded"},
        })
        assert p.payload_transform_info.keyinfo.key_input_type == "fixed"

    def test_hardcoded_key_input_normalizes_to_fixed(self):
        p = _PayloadInfoOutput(payload_transform_info={
            "algorithm": "AES",
            "keyinfo": {"size": 128, "key_input_type": "hardcoded"},
        })
        assert p.payload_transform_info.keyinfo.key_input_type == "fixed"

    def test_user_input_variant_normalizes(self):
        p = _PayloadInfoOutput(payload_transform_info={
            "algorithm": "AES",
            "keyinfo": {"size": 128, "key_input_type": "user input"},
        })
        assert p.payload_transform_info.keyinfo.key_input_type == "user-input"

    def test_invalid_key_input_type_becomes_none(self):
        p = _PayloadInfoOutput(payload_transform_info={
            "algorithm": "RC4",
            "keyinfo": {"size": 16, "key_input_type": "mystery"},
        })
        assert p.payload_transform_info.keyinfo.key_input_type is None

    def test_all_valid_key_input_types_pass(self):
        for kit in _VALID_KEY_INPUT_TYPES:
            p = _PayloadInfoOutput(payload_transform_info={
                "algorithm": "RC4",
                "keyinfo": {"size": 16, "key_input_type": kit},
            })
            assert p.payload_transform_info.keyinfo.key_input_type == kit
