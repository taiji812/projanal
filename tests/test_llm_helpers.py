"""Unit tests for analysis_agent.llm helpers."""

import sys
import types

# Stub langchain_ollama so llm.py can be imported without the full stack
_lco = types.ModuleType("langchain_ollama")
_lco.ChatOllama = type("ChatOllama", (), {"__init__": lambda self, **kw: None})
sys.modules.setdefault("langchain_ollama", _lco)

import os
import pytest
from analysis_agent.llm import thinking_off


class TestThinkingOff:
    def test_qwen_model_appends_no_think(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "qwen3-coder:30b")
        assert thinking_off("PROMPT") == "PROMPT\n/no_think"

    def test_gpt_oss_model_appends_no_think(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "gpt-oss:20b")
        assert thinking_off("PROMPT") == "PROMPT\n/no_think"

    def test_gemma_model_no_directive(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "gemma4:26b-mlx")
        assert thinking_off("PROMPT") == "PROMPT"

    def test_llama_model_no_directive(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "llama3.3:70b")
        assert thinking_off("PROMPT") == "PROMPT"

    def test_empty_model_env_no_directive(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "")
        assert thinking_off("PROMPT") == "PROMPT"

    def test_case_insensitive_match(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "Qwen3:32b")
        assert thinking_off("PROMPT") == "PROMPT\n/no_think"

    def test_no_think_appended_once(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "qwen3-coder:30b")
        result = thinking_off("line1\nline2")
        assert result.count("/no_think") == 1
        assert result.endswith("/no_think")
