"""LanguageAnalyzer node — heuristic line-count based, no LLM needed."""
from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import count_lines_by_extension

# Map file extensions to canonical language names
_EXT_TO_LANG: dict[str, str] = {
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++", ".cxx": "C++", ".cc": "C++", ".c++": "C++",
    ".hpp": "C++ Header", ".hxx": "C++ Header", ".hh": "C++ Header",
    ".cs": "C#",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".jsx": "JavaScript (JSX)",
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

# Extensions to exclude from language stats (config/data/docs)
_IGNORE_EXTS = {
    ".md", ".txt", ".rst", ".html", ".htm", ".css",
    ".svg", ".png", ".jpg", ".lock", ".sum",
}


def language_analyzer_node(state: AnalysisState) -> dict:
    repo_path = state["repo_path"]

    try:
        raw_counts = count_lines_by_extension(repo_path)
    except Exception as e:
        return {"language_composition": {}, "completed_nodes": ["language_analyzer"], "errors": [f"language_analyzer: {e}"]}

    # Aggregate by language
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
        "completed_nodes": ["language_analyzer"],
        "errors": [],
    }
