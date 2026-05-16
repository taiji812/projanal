"""Tree-sitter based semantic chunker.

Supported strategies:
  - MSBuild XML (.csproj / .vcxproj / .props) → PropertyGroup/ItemGroup sections via xml.etree
  - .sln                                       → project reference list via regex
  - Makefile                                   → target blocks via regex
  - Source files (C#/C/C++/Go/Rust/Java/…)     → top-level declarations via tree-sitter AST
  - Everything else                             → sliding-window line chunks (fallback)
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

try:
    from tree_sitter import Language, Parser as _TSParser
    _HAS_TS = True
except ImportError:
    _HAS_TS = False

# Lazy-loaded language → Parser cache
_parser_cache: dict[str, "_TSParser"] = {}


def _get_ts_parser(lang: str) -> "_TSParser":
    """Return a cached tree-sitter Parser for the given language name."""
    if lang in _parser_cache:
        return _parser_cache[lang]

    _mod_map = {
        "c_sharp":    "tree_sitter_c_sharp",
        "cpp":        "tree_sitter_cpp",
        "c":          "tree_sitter_c",
        "go":         "tree_sitter_go",
        "rust":       "tree_sitter_rust",
        "java":       "tree_sitter_java",
        "python":     "tree_sitter_python",
        "javascript": "tree_sitter_javascript",
        "typescript": "tree_sitter_typescript",
        "bash":       "tree_sitter_bash",
    }
    mod_name = _mod_map.get(lang)
    if not mod_name:
        raise ImportError(f"No tree-sitter grammar for {lang}")

    import importlib
    mod = importlib.import_module(mod_name)

    # tree-sitter-typescript exposes two languages
    if lang == "typescript":
        ts_lang = Language(mod.language_typescript())
    else:
        ts_lang = Language(mod.language())

    parser = _TSParser(ts_lang)
    _parser_cache[lang] = parser
    return parser


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Chunk:
    id: str
    content: str
    file_path: str
    start_line: int
    end_line: int
    language: str
    chunk_type: str   # function | class | config_section | directive | text
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Extension → tree-sitter language name
# ---------------------------------------------------------------------------

_EXT_LANG: dict[str, str] = {
    ".cs":   "c_sharp",
    ".c":    "c",
    ".cpp":  "cpp",  ".cc": "cpp",  ".cxx": "cpp",
    ".h":    "cpp",  ".hpp": "cpp",
    ".go":   "go",
    ".rs":   "rust",
    ".java": "java",
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".cmake": "cmake",
    ".sh":   "bash",
}

# AST node types to treat as chunk boundaries, per language.
# We recurse the full tree and emit a chunk for every matching node
# (so methods inside classes each become their own chunk).
_CHUNK_NODE_TYPES: dict[str, set[str]] = {
    "c_sharp": {
        "method_declaration", "constructor_declaration",
        "class_declaration", "interface_declaration",
        "enum_declaration", "namespace_declaration",
        "using_directive",
    },
    "cpp": {
        "function_definition", "class_specifier", "struct_specifier",
        "namespace_definition",
        "preproc_include", "preproc_def", "preproc_ifdef",
    },
    "c": {
        "function_definition", "struct_specifier",
        "preproc_include", "preproc_def", "preproc_ifdef",
    },
    "go": {
        "function_declaration", "method_declaration",
        "type_declaration", "import_declaration",
    },
    "rust": {
        "function_item", "impl_item", "struct_item",
        "enum_item", "trait_item", "use_declaration",
    },
    "java": {
        "class_declaration", "interface_declaration",
        "method_declaration", "import_declaration",
    },
    "python": {
        "function_definition", "class_definition",
        "import_statement", "import_from_statement",
    },
    "cmake": {
        "function_def", "normal_command",
    },
    "bash": {
        "function_definition",
    },
    "javascript": {
        "function_declaration", "arrow_function", "method_definition",
        "class_declaration", "import_statement", "export_statement",
    },
    "typescript": {
        "function_declaration", "arrow_function", "method_definition",
        "class_declaration", "import_statement", "export_statement",
        "interface_declaration", "type_alias_declaration",
    },
}

# Max lines per chunk before truncation
_MAX_CHUNK_LINES = 120
_FALLBACK_CHUNK_LINES = 60
_FALLBACK_OVERLAP = 10


# ---------------------------------------------------------------------------
# Keyword → tag mapping (applied to chunk content for pre-filtering)
# ---------------------------------------------------------------------------

_TAG_RE: dict[str, re.Pattern] = {
    "network":     re.compile(r"TcpClient|Socket\b|WSAStartup|HttpClient|WebClient|connect\s*\(|recv\s*\(|send\s*\(|SslStream", re.I),
    "persistence": re.compile(r"Registry\b|RunKey|Startup|AutoRun|HKCU|HKLM|RegistryKey|SetRegistry", re.I),
    "injection":   re.compile(r"VirtualAlloc|CreateRemoteThread|WriteProcessMemory|NtCreateThread|inject", re.I),
    "evasion":     re.compile(r"AntiDebug|Anti.Analysis|IsDebuggerPresent|CheckRemoteDebugger|sandbox|vmware|VM_|MutexControl", re.I),
    "keylogger":   re.compile(r"GetAsyncKeyState|SetWindowsHookEx|keylog|WH_KEYBOARD|KeyLogger|LimeLogger", re.I),
    "screenshot":  re.compile(r"screenshot|CopyFromScreen|BitBlt|PrintWindow|Bitmap\b|RemoteDesktop", re.I),
    "credential":  re.compile(r"password|credential|recover|harvest|lsass|mimikatz|token\b|stealer", re.I),
    "build":       re.compile(r"add_executable|add_library|OutputType|AssemblyName|cmake_minimum|MSBuild|Makefile|Cargo\.toml|go\.mod", re.I),
    "artifact":    re.compile(r"OutputPath|AssemblyName|OutputType|add_executable|WinExe|Library\b|install\s*\(", re.I),
    "c2":          re.compile(r"beacon|implant|\bc2\b|command.and.control|\bRAT\b|backdoor", re.I),
    "execution":   re.compile(r"Process\.Start|ProcessStartInfo|CreateProcess|ShellExecute|WMI|cmd\.exe|powershell", re.I),
}


def _assign_tags(text: str) -> list[str]:
    return [tag for tag, pat in _TAG_RE.items() if pat.search(text)]


def _make_id(file_path: str, suffix: str) -> str:
    raw = f"{file_path}::{suffix}"
    return raw[:500]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def chunk_file(rel_path: str, content: str) -> list[Chunk]:
    ext  = Path(rel_path).suffix.lower()
    name = Path(rel_path).name.lower()

    if ext in (".csproj", ".vcxproj", ".props"):
        return _chunk_msbuild_xml(rel_path, content)

    if ext == ".sln":
        return _chunk_sln(rel_path, content)

    if name in ("makefile", "gnumakefile") or ext == ".mk":
        return _chunk_makefile(rel_path, content)

    lang = _EXT_LANG.get(ext)
    if lang and _HAS_TS:
        try:
            chunks = _chunk_source(rel_path, content, lang)
            return chunks if chunks else _chunk_lines(rel_path, content, lang)
        except Exception:
            pass

    return _chunk_lines(rel_path, content, lang or "text")


# ---------------------------------------------------------------------------
# MSBuild XML (.csproj / .vcxproj)
# ---------------------------------------------------------------------------

def _chunk_msbuild_xml(rel_path: str, content: str) -> list[Chunk]:
    clean = content.lstrip("﻿")
    clean = re.sub(r'\s+xmlns(?::[^=]+)?="[^"]+"', "", clean)
    try:
        root = ET.fromstring(clean)
    except ET.ParseError:
        return _chunk_lines(rel_path, content, "xml")

    def strip_ns(tag: str) -> str:
        return tag.split("}")[-1] if "}" in tag else tag

    chunks: list[Chunk] = []
    for elem in root.iter():
        tag = strip_ns(elem.tag)
        if tag not in ("PropertyGroup", "ItemGroup"):
            continue
        condition = elem.get("Condition", "default").strip()
        lines = []
        for child in elem:
            child_tag = strip_ns(child.tag)
            val = (child.text or "").strip()
            if val:
                lines.append(f"  {child_tag}: {val}")
        if not lines:
            continue
        body = f"{tag}[{condition}]:\n" + "\n".join(lines)
        chunks.append(Chunk(
            id=_make_id(rel_path, f"{tag}_{condition}_{len(chunks)}"),
            content=body,
            file_path=rel_path,
            start_line=0, end_line=0,
            language="msbuild_xml",
            chunk_type="config_section",
            tags=_assign_tags(body),
        ))

    return chunks or _chunk_lines(rel_path, content, "xml")


# ---------------------------------------------------------------------------
# Visual Studio .sln
# ---------------------------------------------------------------------------

_SLN_PROJECT_RE = re.compile(
    r'Project\("[^"]+"\)\s*=\s*"([^"]+)"\s*,\s*"([^"]+)"',
    re.I,
)

def _chunk_sln(rel_path: str, content: str) -> list[Chunk]:
    matches = _SLN_PROJECT_RE.findall(content)
    if not matches:
        return []
    body = "Solution project references:\n" + "\n".join(
        f"  {name}: {path}" for name, path in matches
    )
    return [Chunk(
        id=_make_id(rel_path, "project_list"),
        content=body,
        file_path=rel_path,
        start_line=0, end_line=0,
        language="sln",
        chunk_type="config_section",
        tags=["build"],
    )]


# ---------------------------------------------------------------------------
# Makefile
# ---------------------------------------------------------------------------

_MAKEFILE_TARGET_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_\-\.]*)\s*:", re.M)

def _chunk_makefile(rel_path: str, content: str) -> list[Chunk]:
    targets = [(m.group(1), m.start()) for m in _MAKEFILE_TARGET_RE.finditer(content)]
    if not targets:
        return _chunk_lines(rel_path, content, "makefile")

    chunks: list[Chunk] = []
    for i, (tgt, char_pos) in enumerate(targets):
        end_char = targets[i + 1][1] if i + 1 < len(targets) else len(content)
        body = content[char_pos:end_char].strip()
        if len(body) > 2000:
            body = body[:2000] + "\n... [truncated]"
        chunks.append(Chunk(
            id=_make_id(rel_path, f"target_{tgt}"),
            content=f"make target: {tgt}\n{body}",
            file_path=rel_path,
            start_line=0, end_line=0,
            language="makefile",
            chunk_type="directive",
            tags=_assign_tags(body) + ["build"],
        ))
    return chunks


# ---------------------------------------------------------------------------
# Tree-sitter source file chunking
# ---------------------------------------------------------------------------

def _collect_nodes(node, target_types: set[str], result: list, depth: int = 0, max_depth: int = 10) -> None:
    """Recursively collect AST nodes whose type is in target_types."""
    if depth > max_depth:
        return
    if node.type in target_types:
        result.append(node)
        # still recurse: methods inside class_declaration are also collected
    for child in node.children:
        _collect_nodes(child, target_types, result, depth + 1, max_depth)


def _chunk_source(rel_path: str, content: str, lang: str) -> list[Chunk]:
    target_types = _CHUNK_NODE_TYPES.get(lang)
    if not target_types:
        return []

    parser = _get_ts_parser(lang)
    source_bytes = content.encode("utf-8", errors="replace")
    tree = parser.parse(source_bytes)
    lines = content.splitlines()

    found: list = []
    _collect_nodes(tree.root_node, target_types, found)
    if not found:
        return []

    chunks: list[Chunk] = []
    for node in found:
        start = node.start_point[0]
        end   = node.end_point[0]
        span  = end - start

        if span > _MAX_CHUNK_LINES:
            node_lines = lines[start : start + _MAX_CHUNK_LINES]
            body = "\n".join(node_lines) + f"\n... [{span} lines total, truncated]"
        else:
            body = "\n".join(lines[start : end + 1])

        if not body.strip():
            continue

        if "function" in node.type or "method" in node.type or "constructor" in node.type:
            chunk_type = "function"
        elif "class" in node.type or "struct" in node.type or "impl" in node.type:
            chunk_type = "class"
        else:
            chunk_type = "directive"

        chunks.append(Chunk(
            id=_make_id(rel_path, f"L{start}_{node.type}"),
            content=body,
            file_path=rel_path,
            start_line=start,
            end_line=end,
            language=lang,
            chunk_type=chunk_type,
            tags=_assign_tags(body),
        ))

    return chunks


# ---------------------------------------------------------------------------
# Fallback: sliding-window line chunks
# ---------------------------------------------------------------------------

def _chunk_lines(rel_path: str, content: str, lang: str) -> list[Chunk]:
    lines = content.splitlines()
    chunks: list[Chunk] = []
    step = max(1, _FALLBACK_CHUNK_LINES - _FALLBACK_OVERLAP)

    for i in range(0, len(lines), step):
        body = "\n".join(lines[i : i + _FALLBACK_CHUNK_LINES])
        if not body.strip():
            continue
        chunks.append(Chunk(
            id=_make_id(rel_path, f"lines_{i}"),
            content=body,
            file_path=rel_path,
            start_line=i,
            end_line=min(i + _FALLBACK_CHUNK_LINES, len(lines)),
            language=lang,
            chunk_type="text",
            tags=_assign_tags(body),
        ))
    return chunks
