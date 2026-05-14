import os
import re
from pathlib import Path

# Extensions to skip entirely (binary, media, etc.)
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".exe", ".dll", ".so", ".dylib", ".lib", ".a", ".o", ".obj",
    ".bin", ".dat", ".db", ".sqlite",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".ttf", ".otf", ".woff", ".woff2",
    ".pyc", ".pyo", ".class", ".jar",
}

_SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__",
    ".idea", ".vscode", "vendor", "third_party", "thirdparty",
    "build", "dist", "out", "target", "bin", "obj",
    ".gradle", ".mvn", "coverage", ".nyc_output",
}


def list_directory(root: str, max_depth: int = 4) -> list[str]:
    """Return relative file paths up to max_depth, skipping binary/generated dirs."""
    root_path = Path(root)
    results: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # prune skipped dirs in-place so os.walk won't recurse into them
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]

        rel_dir = Path(dirpath).relative_to(root_path)
        depth = len(rel_dir.parts)
        if depth >= max_depth:
            dirnames.clear()
            continue

        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext not in _SKIP_EXTENSIONS:
                results.append(str(rel_dir / fname))

    return sorted(results)


def read_file(root: str, rel_path: str, max_bytes: int = 32_768) -> str:
    """Read a file relative to root. Truncates at max_bytes."""
    full_path = Path(root) / rel_path
    if not full_path.exists():
        return ""
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
        if len(content) == max_bytes:
            content += "\n... [truncated]"
        return content
    except Exception:
        return ""


def find_files_by_name(root: str, names: list[str]) -> dict[str, str]:
    """Find files matching given names anywhere in the tree. Returns {name: first_match_rel_path}."""
    names_lower = {n.lower(): n for n in names}
    found: dict[str, str] = {}
    root_path = Path(root)

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            key = fname.lower()
            if key in names_lower and names_lower[key] not in found:
                rel = str(Path(dirpath).relative_to(root_path) / fname)
                found[names_lower[key]] = rel

    return found


def find_files_by_extension(root: str, extensions: list[str]) -> list[str]:
    """Find all files with given extensions. Returns relative paths."""
    exts = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions}
    results: list[str] = []
    root_path = Path(root)

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            if Path(fname).suffix.lower() in exts:
                rel = str(Path(dirpath).relative_to(root_path) / fname)
                results.append(rel)

    return sorted(results)


def grep_content(root: str, pattern: str, extensions: list[str] | None = None, max_matches: int = 50) -> list[dict]:
    """Search file contents for a regex pattern. Returns list of {file, line, text}."""
    regex = re.compile(pattern, re.IGNORECASE)
    root_path = Path(root)
    matches: list[dict] = []
    exts = None
    if extensions:
        exts = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions}

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            if Path(fname).suffix.lower() in _SKIP_EXTENSIONS:
                continue
            if exts and Path(fname).suffix.lower() not in exts:
                continue
            full = Path(dirpath) / fname
            rel = str(Path(dirpath).relative_to(root_path) / fname)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        if regex.search(line):
                            matches.append({"file": rel, "line": lineno, "text": line.rstrip()})
                            if len(matches) >= max_matches:
                                return matches
            except Exception:
                continue

    return matches


def count_lines_by_extension(root: str) -> dict[str, int]:
    """Count source lines per file extension."""
    counts: dict[str, int] = {}
    root_path = Path(root)

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext in _SKIP_EXTENSIONS or not ext:
                continue
            full = Path(dirpath) / fname
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    line_count = sum(1 for _ in f)
                counts[ext] = counts.get(ext, 0) + line_count
            except Exception:
                continue

    return counts
