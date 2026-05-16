"""Unit tests for _enrich_mitre() in tactic_classifier."""

import sys
import types

# Stub out heavy runtime dependencies so the module can be imported without
# a full langchain / ollama installation.
_langchain_ollama = types.ModuleType("langchain_ollama")
_langchain_ollama.ChatOllama = type("ChatOllama", (), {})  # type: ignore[attr-defined]
sys.modules.setdefault("langchain_ollama", _langchain_ollama)

_state_mod = types.ModuleType("analysis_agent.state")
_state_mod.AnalysisState = dict  # type: ignore[attr-defined]
sys.modules.setdefault("analysis_agent.state", _state_mod)

_fs_mod = types.ModuleType("analysis_agent.tools.filesystem")
_fs_mod.grep_content = lambda *a, **kw: []  # type: ignore[attr-defined]
_fs_mod.read_file = lambda *a, **kw: ""  # type: ignore[attr-defined]
sys.modules.setdefault("analysis_agent.tools.filesystem", _fs_mod)
sys.modules.setdefault("analysis_agent.tools", types.ModuleType("analysis_agent.tools"))

import pytest

from analysis_agent.nodes.tactic_classifier import _enrich_mitre


def test_keylogger_tag_adds_technique_and_tactic():
    tactics, techniques = _enrich_mitre([], [], ["Keylogger"], "")
    assert "T1056" in techniques
    assert "TA0009" in tactics


def test_c2_framework_tag_adds_technique_and_tactic():
    tactics, techniques = _enrich_mitre([], [], ["C2 Framework"], "")
    assert "T1095" in techniques
    assert "TA0011" in tactics


def test_context_process_start_adds_execution():
    tactics, techniques = _enrich_mitre([], [], [], "Process.Start(\"calc.exe\")")
    assert "T1059" in techniques
    assert "TA0002" in tactics


def test_context_get_async_key_state_adds_collection():
    tactics, techniques = _enrich_mitre([], [], [], "GetAsyncKeyState(vKey)")
    assert "T1056" in techniques
    assert "TA0009" in tactics


def test_llm_provided_ids_are_preserved():
    llm_tactics = ["TA0040"]
    llm_techniques = ["T1486"]
    tactics, techniques = _enrich_mitre(llm_tactics, llm_techniques, [], "")
    assert "TA0040" in tactics
    assert "T1486" in techniques


def test_empty_tags_and_context_returns_empty_lists():
    tactics, techniques = _enrich_mitre([], [], [], "")
    assert tactics == []
    assert techniques == []


def test_results_are_sorted():
    tactics, techniques = _enrich_mitre([], [], ["C2 Framework", "Keylogger"], "")
    assert tactics == sorted(tactics)
    assert techniques == sorted(techniques)


def test_multiple_tags_accumulate_without_duplicates():
    tactics, techniques = _enrich_mitre([], [], ["Keylogger", "C2 Framework"], "")
    assert tactics.count("TA0009") == 1
    assert tactics.count("TA0011") == 1


def test_llm_ids_combined_with_tag_enrichment():
    tactics, techniques = _enrich_mitre(["TA0040"], ["T1486"], ["Keylogger"], "")
    assert "TA0040" in tactics
    assert "T1486" in techniques
    assert "TA0009" in tactics
    assert "T1056" in techniques


def test_context_signal_does_not_duplicate_llm_technique():
    tactics, techniques = _enrich_mitre(["TA0002"], ["T1059"], [], "Process.Start()")
    assert techniques.count("T1059") == 1
    assert tactics.count("TA0002") == 1
