"""LanguageAnalyzer node — heuristic line-count based, no LLM needed."""
from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import count_lines_by_extension

_EXT_TO_LANG: dict[str, str] = {
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++", ".cxx": "C++", ".cc": "C++", ".c++": "C++",
    ".hpp": "C++ Header", ".hxx": "C++ Header", ".hh": "C++ Header",
    ".cs": "C#",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".js": "Javascript", ".mjs": "Javascript", ".cjs": "Javascript",
    ".ts": "Typescript", ".tsx": "Typescript",
    ".jsx": "Javascript",
    ".py": "Python",
    ".rb": "Ruby",
    ".kt": "Kotlin", ".kts": "Kotlin",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".psd1": "PowerShell",
    ".bat": "Batch", ".cmd": "Batch",
    ".cmake": "CMake",
    ".gradle": "Gradle",
    ".xml": "XML",
    ".json": "JSON",
    ".yaml": "YAML", ".yml": "YAML",
    ".toml": "TOML",
    ".proto": "Protobuf",
    ".asm": "Assembly", ".s": "Assembly",
    ".lua": "Lua",
    ".pl": "Perl",
    ".r": "R",
    ".scala": "Scala",
    ".dart": "Dart",
    ".nim": "Nim",
    ".zig": "Zig",
    ".f90": "Fortran", ".f": "Fortran",
}

_IGNORE_EXTS = {
    ".md", ".txt", ".rst", ".html", ".htm", ".css",
    ".svg", ".png", ".jpg", ".lock", ".sum",
}

# Consolidate C/C++ family into a single canonical name
_LANG_CONSOLIDATION: dict[str, str] = {
    "C": "C/C++",
    "C++": "C/C++",
    "C/C++ Header": "C/C++",
    "C++ Header": "C/C++",
}

# Non-programming config/data languages excluded from source_language
_CONFIG_LANGS = {
    "XML", "JSON", "YAML", "TOML", "CMake", "Gradle",
    "Batch", "Shell", "PowerShell", "Protobuf",
}

# Valid SOURCECODE vocab from service VO
_SOURCECODE_VOCAB = frozenset([
    "Assembly", "C/C++", "C#", "Dlang", "Docker", "Golang", "Java",
    "Javascript", "Nim", "Perl", "PHP", "Python", "Ruby", "Rust",
    "Shell", "Sleep", "Typescript", "VBA", "Etc.",
])

# Map internal lang names → SOURCECODE vocab names
_TO_SOURCECODE: dict[str, str] = {
    "Go": "Golang",
}


def _normalize_to_sourcecode_vocab(lang: str) -> str:
    if lang in _TO_SOURCECODE:
        return _TO_SOURCECODE[lang]
    return lang if lang in _SOURCECODE_VOCAB else "Etc."


def _derive_source_language(composition: dict[str, float]) -> list[str]:
    """Convert composition dict to consolidated, SOURCECODE-vocab source language list."""
    consolidated: dict[str, float] = {}
    for lang, ratio in composition.items():
        canonical = _LANG_CONSOLIDATION.get(lang, lang)
        consolidated[canonical] = consolidated.get(canonical, 0.0) + ratio

    seen: set[str] = set()
    result: list[str] = []
    for lang, ratio in sorted(consolidated.items(), key=lambda x: -x[1]):
        if ratio <= 0.03 or lang in _CONFIG_LANGS or lang.startswith("Other ("):
            continue
        vocab_lang = _normalize_to_sourcecode_vocab(lang)
        if vocab_lang not in seen:
            seen.add(vocab_lang)
            result.append(vocab_lang)
        if len(result) >= 3:
            break
    return result


def language_analyzer_node(state: AnalysisState) -> dict:
    repo_path = state["repo_path"]

    try:
        raw_counts = count_lines_by_extension(repo_path)
    except Exception as e:
        return {
            "language_composition": {},
            "source_language": [],
            "completed_nodes": ["language_analyzer"],
            "errors": [f"language_analyzer: {e}"],
        }

    lang_lines: dict[str, int] = {}
    for ext, count in raw_counts.items():
        if ext in _IGNORE_EXTS:
            continue
        lang = _EXT_TO_LANG.get(ext, f"Other ({ext})")
        lang_lines[lang] = lang_lines.get(lang, 0) + count

    total = sum(lang_lines.values()) or 1
    composition = {
        lang: round(lines / total, 4)
        for lang, lines in sorted(lang_lines.items(), key=lambda x: -x[1])
        if lines > 0
    }

    return {
        "language_composition": composition,
        "source_language": _derive_source_language(composition),
        "completed_nodes": ["language_analyzer"],
        "errors": [],
    }
