"""ArtifactAnalyzer node — infers execution components and optional payload info.

Context source (in priority order):
  1. RAG retrieval from ChromaDB
  2. Fallback: direct file reads
"""

import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

from analysis_agent.llm import get_ollama, thinking_off
from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import find_files_by_extension, read_file


# ---------------------------------------------------------------------------
# Pydantic models matching ExecutionFeatures / PayloadInfo schema
# ---------------------------------------------------------------------------

class _ExecutionComponent(BaseModel):
    name: str
    exec_arch: list[str] = Field(default_factory=list)
    exec_os: list[str] = Field(default_factory=list)
    exec_type: list[str] = Field(default_factory=list)
    exec_dependency: list[str] = Field(default_factory=list)
    multi_instance: bool = False
    pathname: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: dict) -> dict:
        # Accept common LLM field variants
        if not data.get("pathname") and data.get("filename"):
            data["pathname"] = data["filename"]
        # Coerce string to list for list fields (LLM sometimes returns a string)
        for field in ("exec_type", "exec_arch", "exec_os", "exec_dependency"):
            val = data.get(field)
            if isinstance(val, str):
                data[field] = [val] if val else []
        if not data.get("exec_type") and data.get("artifact_type"):
            data["exec_type"] = [data["artifact_type"]]
        if not data.get("exec_os"):
            data["exec_os"] = ["windows"]
        if not data.get("exec_arch"):
            data["exec_arch"] = ["x86", "x64"]
        return data


class _ExecutionFeaturesOutput(BaseModel):
    components: list[_ExecutionComponent] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _unwrap(cls, data: dict) -> dict:
        if isinstance(data, list):
            return {"components": data}
        for key in ("artifacts", "items", "outputs"):
            if key in data and "components" not in data:
                data["components"] = data[key]
        return data


class _KeyInfo(BaseModel):
    size: Optional[int] = None
    key_input_type: Optional[str] = None


class _PayloadTransformInfo(BaseModel):
    algorithm: Optional[str] = None
    keyinfo: Optional[_KeyInfo] = None


_VALID_EXECUTION_METHODS = frozenset([
    "process-hollowing", "process-herpaderping", "process-doppleganging",
    "process-ghosting", "reflective-loading", ".net-assembly-loading",
    "early-bird-injection", "thread-hijacking-injection",
    "npmap-unmapviewofsection-injection", "propagate-injection",
    "userdata-injection", "ewmi-injection", "atom-bombing",
    "kernelcontroltable-injection", "ctrl-injection",
    "alpc-injection", "queue-user-apc-injection", "custom-injection",
])

_EXECUTION_METHOD_NORMALIZE: dict[str, str] = {
    "reflective": "reflective-loading",
    "reflective loading": "reflective-loading",
    "reflective-dll-injection": "reflective-loading",
    "process injection": "custom-injection",
    "process hollowing": "process-hollowing",
    "dll injection": "reflective-loading",
    "clr loading": ".net-assembly-loading",
    "clr-loading": ".net-assembly-loading",
    ".net assembly loading": ".net-assembly-loading",
    "apc injection": "queue-user-apc-injection",
    "thread hijacking": "thread-hijacking-injection",
    "early bird injection": "early-bird-injection",
    "early bird": "early-bird-injection",
    "atom bombing": "atom-bombing",
    "process doppelganging": "process-doppleganging",
    "process ghosting": "process-ghosting",
    "process herpaderping": "process-herpaderping",
    "shellcode execution": "custom-injection",
    "shellcode-exec": "custom-injection",
}

_VALID_EMBEDDING_TYPES = frozenset(["resource", "overlay", "data", "text"])

_EMBEDDING_TYPE_NORMALIZE: dict[str, str] = {
    "clr": "resource",
    "dll": "data",
    "embedded": "data",
    "pe": "data",
    "resource section": "resource",
    "overlay section": "overlay",
    "text section": "text",
    "resources": "resource",
}

_VALID_KEY_INPUT_TYPES = frozenset(["fixed", "user-input", "file"])

_KEY_INPUT_TYPE_NORMALIZE: dict[str, str] = {
    "embedded": "fixed",
    "hardcoded": "fixed",
    "static": "fixed",
    "hard-coded": "fixed",
    "user input": "user-input",
    "userinput": "user-input",
    "user_input": "user-input",
    "from file": "file",
    "file-based": "file",
    "file_based": "file",
}


class _PayloadInfoOutput(BaseModel):
    payload_exec_type: list[str] = Field(default_factory=list)
    execution_method: list[str] = Field(default_factory=list)
    execution_technique_notes: list[str] = Field(default_factory=list)
    payload_target_path: Optional[str] = None
    delivery_type: Optional[str] = None
    payload_transform_info: Optional[_PayloadTransformInfo] = None
    embedding_type: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_vocab(cls, data: dict) -> dict:
        # Normalize embedding_type
        et = data.get("embedding_type")
        if et:
            norm = _EMBEDDING_TYPE_NORMALIZE.get(str(et).lower(), et)
            data["embedding_type"] = norm if norm in _VALID_EMBEDDING_TYPES else None

        # Normalize execution_method to valid vocab
        methods = data.get("execution_method", [])
        if isinstance(methods, list):
            seen: set[str] = set()
            normalized: list[str] = []
            for m in methods:
                nm = _EXECUTION_METHOD_NORMALIZE.get(str(m).lower(), m)
                if nm in _VALID_EXECUTION_METHODS and nm not in seen:
                    seen.add(nm)
                    normalized.append(nm)
            data["execution_method"] = normalized

        # Normalize key_input_type inside payload_transform_info.keyinfo
        pti = data.get("payload_transform_info")
        if isinstance(pti, dict):
            ki = pti.get("keyinfo")
            if isinstance(ki, dict):
                kit = ki.get("key_input_type")
                if kit:
                    norm_kit = _KEY_INPUT_TYPE_NORMALIZE.get(str(kit).lower(), kit)
                    ki["key_input_type"] = norm_kit if norm_kit in _VALID_KEY_INPUT_TYPES else None

        return data


class _ArtifactAnalysisOutput(BaseModel):
    execution_features: _ExecutionFeaturesOutput = Field(
        default_factory=_ExecutionFeaturesOutput
    )
    payload_info: Optional[_PayloadInfoOutput] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: dict) -> dict:
        # LLM may return flat {components: [...]} without the execution_features wrapper
        if "components" in data and "execution_features" not in data:
            data["execution_features"] = {"components": data.pop("components")}
        return data


# ---------------------------------------------------------------------------
# Deterministic crypto algorithm detection
# ---------------------------------------------------------------------------

# Patterns that indicate the ACTUAL encryption algorithm (not key derivation)
_CRYPTO_DETECT: list[tuple[re.Pattern, str]] = [
    # RC4: named function, comment, or KSA/PRGA markers
    (re.compile(
        r'\bRC4\b|RC4\s*암호|Key-scheduling algorithm|KSA\b|PRGA\b|Pseudo-random generation algorithm',
        re.I,
    ), "RC4"),
    # AES: via BCrypt AES constant or named encrypt/decrypt function
    (re.compile(
        r'BCRYPT_AES_ALGORITHM|AES_encrypt|AES_decrypt|AesEncrypt|AesDecrypt'
        r'|RijndaelManaged|Aes\.Create\(\)|CryptEncrypt.*AES',
        re.I,
    ), "AES"),
    # ChaCha20 / Salsa20
    (re.compile(r'chacha20|ChaCha20|salsa20', re.I), "ChaCha20"),
    # XOR-based stream
    (re.compile(r'xor_encrypt|xor_key|encrypt_xor|xor_stream|\bXOR\s+cipher', re.I), "XOR"),
    # DES / 3DES
    (re.compile(r'BCRYPT_3DES_ALGORITHM|BCRYPT_DES_ALGORITHM|\bTripleDES\b|\b3DES\b', re.I), "3DES"),
    # Blowfish
    (re.compile(r'\bBlowfish\b', re.I), "Blowfish"),
]

# SHA-based BCrypt calls are key DERIVATION, not encryption — do not confuse with AES
_SHA_BCRYPT_ONLY = re.compile(
    r'BCryptOpenAlgorithmProvider\s*\([^)]*BCRYPT_SHA\d+_ALGORITHM',
    re.I | re.DOTALL,
)


def _detect_crypto_algorithm(context: str) -> str | None:
    """Deterministically detect the payload encryption algorithm from code context.

    Returns the algorithm name (e.g. "RC4", "AES") or None if undetermined.
    BCrypt calls that only use SHA for key derivation are intentionally ignored.
    """
    for pattern, algo in _CRYPTO_DETECT:
        if pattern.search(context):
            return algo
    return None


def _detect_crypto_from_files(repo_path: str) -> str | None:
    """Fallback: grep source files directly when RAG context missed the crypto code."""
    from analysis_agent.tools.filesystem import grep_content
    for pattern, algo in _CRYPTO_DETECT:
        hits = grep_content(
            repo_path,
            pattern.pattern,
            extensions=[".c", ".cpp", ".h", ".cs", ".py", ".go", ".rs"],
            max_matches=1,
        )
        if hits:
            return algo
    return None


# ---------------------------------------------------------------------------
# RAG retrieval
# ---------------------------------------------------------------------------

_ARTIFACT_QUERIES = [
    "executable binary output assembly name filename",
    "OutputPath OutputType AssemblyName WinExe Library dotnet",
    "add_executable add_library install cmake target",
    "jar war artifact maven gradle package",
    "cargo bin lib rust output",
    "payload loader inject reflective CLR shellcode",
    # Dedicated crypto query — pulls encrypter/crypto source into context
    "RC4 AES encryption decrypt cipher key schedule algorithm encrypt payload",
    # Build event queries — needed to identify build-time helper tools
    "PreBuildEvent PostBuildEvent CustomBuildStep Exec Command post-build tool invoke",
]


def _rag_context(project_id: str) -> str:
    from analysis_agent.indexer.store import get_project_collection, retrieve_multi
    col = get_project_collection(project_id)
    if col is None or col.count() == 0:
        return ""
    return retrieve_multi(project_id, _ARTIFACT_QUERIES, n_per_query=4)


# ---------------------------------------------------------------------------
# Build event tool detection — deterministic extraction of binaries used as
# build-time helpers so they can be filtered out of execution_features.components
# ---------------------------------------------------------------------------

# Regex to pull executable filenames from shell-style command strings.
# Matches the basename of any path ending in a known executable extension.
_CMD_EXEC_RE = re.compile(
    r'(?:^|[\s"\'])(?:[A-Za-z]:[/\\]|\.{0,2}[/\\])?'
    r'(?:[^"\'\s/\\]*[/\\])*'
    r'([^"\'\s/\\]+\.(?:exe|bat|cmd|ps1|sh|py))',
    re.IGNORECASE,
)

# Strips MSBuild $(Macro) / Make $(VAR) / shell ${VAR} references so that
# "$(OutDir)Encrypter.exe" becomes "/Encrypter.exe" and the basename is found correctly.
_MACRO_RE = re.compile(r'\$[({][^})]*[})]')

# MSBuild XML namespace prefix used in .vcxproj / .csproj files
_MSB_NS = "http://schemas.microsoft.com/developer/msbuild/2003"


def _exe_names_from_command(command: str) -> set[str]:
    """Extract lowercase executable basenames from a build command string."""
    # Replace macro references with a path separator so the regex finds the basename
    normalized = _MACRO_RE.sub("/", command)
    return {m.group(1).lower() for m in _CMD_EXEC_RE.finditer(normalized)}


def _resolve_msbuild_target_macros(cmd: str, assembly_name: str) -> str:
    """Replace $(TargetName)/$(TargetFileName)/$(TargetPath) with resolved values.

    MSBuild expands these to the project's output binary name at build time.
    We substitute them here so _exe_names_from_command can extract the real filename.
    """
    resolved = re.sub(r'\$\(TargetName\)', assembly_name, cmd, flags=re.IGNORECASE)
    resolved = re.sub(r'\$\(TargetFileName\)', f"{assembly_name}.exe", resolved, flags=re.IGNORECASE)
    # $(TargetPath) expands to a full path; replace with /name.exe so basename extraction works
    resolved = re.sub(r'\$\(TargetPath\)', f"/{assembly_name}.exe", resolved, flags=re.IGNORECASE)
    return resolved


def _parse_msbuild_project(path: str) -> set[str]:
    """Return executable names invoked in MSBuild build events / Exec tasks."""
    tools: set[str] = set()
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        # Handle both namespaced and bare elements
        ns = _MSB_NS if root.tag.startswith("{") else ""
        ns_prefix = f"{{{ns}}}" if ns else ""

        # Fix A: read AssemblyName first so $(TargetName) can be resolved in build events
        assembly_name: str = ""
        for pg in root.iter(f"{ns_prefix}PropertyGroup"):
            for child in pg:
                bare = (child.tag.split("}")[-1] if "}" in child.tag else child.tag)
                if bare == "AssemblyName" and (child.text or "").strip():
                    assembly_name = child.text.strip()
                    break
            if assembly_name:
                break
        if not assembly_name:
            assembly_name = os.path.splitext(os.path.basename(path))[0]

        # Build event tags (vcxproj) and Exec tasks (csproj / Directory.Build.targets)
        event_tags = {
            f"{ns_prefix}PreBuildEvent",
            f"{ns_prefix}PostBuildEvent",
            f"{ns_prefix}CustomBuildStep",
        }
        exec_tag = f"{ns_prefix}Exec"

        for elem in root.iter():
            if elem.tag in event_tags:
                # <Command> child or element text
                cmd_elem = elem.find(f"{ns_prefix}Command")
                cmd_text = (cmd_elem.text if cmd_elem is not None else elem.text) or ""
                cmd_text = _resolve_msbuild_target_macros(cmd_text, assembly_name)
                tools |= _exe_names_from_command(cmd_text)
            elif elem.tag == exec_tag:
                cmd_text = _resolve_msbuild_target_macros(
                    elem.get("Command", ""), assembly_name
                )
                tools |= _exe_names_from_command(cmd_text)
    except Exception:
        pass
    return tools


def _parse_script_file(repo_path: str, rel_path: str) -> set[str]:
    """Extract executable names called in shell/batch/PowerShell build scripts."""
    content = read_file(repo_path, rel_path, max_bytes=8192)
    if not content:
        return set()
    tools: set[str] = set()
    for line in content.splitlines():
        stripped = line.strip()
        # Skip comment lines
        if stripped.startswith(("#", "REM", "::", "//")):
            continue
        tools |= _exe_names_from_command(stripped)
    return tools


def _extract_build_event_tools(repo_path: str, key_files: dict[str, str]) -> set[str]:
    """Return lowercase basenames of all executables invoked as build-time tools.

    Parses PreBuildEvent/PostBuildEvent/CustomBuildStep in .vcxproj/.csproj files
    and executable calls in build scripts to identify helper binaries that should
    NOT appear in execution_features.components.
    """
    tools: set[str] = set()

    # Walk all MSBuild project files in the repo
    for ext in (".vcxproj", ".csproj", ".props", ".targets"):
        for rel_path in find_files_by_extension(repo_path, [ext]):
            abs_path = os.path.join(repo_path, rel_path.lstrip("/\\"))
            tools |= _parse_msbuild_project(abs_path)

    # Walk build scripts identified by file_explorer or by extension scan
    script_roles = ["makefile", "jenkinsfile"]
    for role in script_roles:
        if role in key_files:
            tools |= _parse_script_file(repo_path, key_files[role])

    for rel_path in find_files_by_extension(repo_path, [".bat", ".cmd", ".ps1", ".sh"]):
        tools |= _parse_script_file(repo_path, rel_path)

    # Remove generic system tools that are never project artifacts
    _SYSTEM_TOOLS = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "msbuild.exe", "devenv.exe",
        "cmake.exe", "make.exe", "nmake.exe", "ninja.exe", "cl.exe", "link.exe",
        "python.exe", "python3.exe", "pip.exe", "pip3.exe",
        "git.exe", "git", "xcopy.exe", "copy.exe", "robocopy.exe",
        "signtool.exe", "mt.exe", "rc.exe", "midl.exe",
        "dotnet.exe", "nuget.exe", "cargo.exe", "go.exe",
        "bash", "sh", "bash.exe", "sh.exe",
    }
    return tools - _SYSTEM_TOOLS


# ---------------------------------------------------------------------------
# Deterministic solution/project component extraction
# Parses .sln → .csproj to enumerate final deliverable binaries, then merges
# with LLM output as a safety net for components the LLM missed.
# ---------------------------------------------------------------------------

# Matches Project(...) lines in .sln files to extract relative .csproj paths.
_SLN_PROJECT_RE = re.compile(
    r'Project\("[^"]*"\)\s*=\s*"[^"]*",\s*"([^"]+\.(?:csproj|vcxproj))"',
    re.IGNORECASE,
)

# Detects the self-executing build tool pattern inside PostBuildEvent text:
#   - First non-empty command line starts with $(TargetName).exe or $(TargetPath)
#   - AND the event also deletes that output (del $(TargetDir)$(TargetName).exe)
# Projects matching this (e.g. ClientBuilder, ServerSetting) run their own output
# as a code-generation step and are NOT final deliverables.
_SELF_EXEC_FIRST_LINE_RE = re.compile(
    r'^\s*\$\((?:TargetName|TargetPath|TargetFileName)\)(?:\.exe)?\b',
    re.IGNORECASE,
)
_SELF_DELETE_RE = re.compile(
    r'\bdel\b.+\$\((?:TargetDir|TargetPath|TargetName)\)',
    re.IGNORECASE,
)

# Tags that contain build event command text in .csproj/.vcxproj files
_BUILD_EVENT_TAGS = frozenset([
    "prebuildevent", "postbuildevent", "custombuildstep", "command",
])


def _build_event_texts(csproj_abs: str) -> list[str]:
    """Return all build event command texts from a .csproj/.vcxproj file."""
    texts: list[str] = []
    try:
        tree = ET.parse(csproj_abs)
        root = tree.getroot()
        ns_prefix = f"{{{_MSB_NS}}}" if root.tag.startswith("{") else ""
        for elem in root.iter():
            bare = (elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag).lower()
            if bare in _BUILD_EVENT_TAGS and elem.text:
                texts.append(elem.text)
    except Exception:
        pass
    return texts


def _is_self_executing_build_tool(csproj_abs: str) -> bool:
    """Return True if the project executes and then deletes its own output binary.

    Matches the ClientBuilder / ServerSetting pattern where PostBuildEvent
    starts with $(TargetName).exe and later deletes $(TargetDir)$(TargetName).exe.
    Operates on parsed XML text to avoid inline-tag false negatives.
    """
    for text in _build_event_texts(csproj_abs):
        # Check first non-empty line of the build event
        first_line = next(
            (ln for ln in text.splitlines() if ln.strip()), ""
        )
        if _SELF_EXEC_FIRST_LINE_RE.match(first_line.strip()) and _SELF_DELETE_RE.search(text):
            return True
    return False


def _parse_csproj_component(csproj_abs: str) -> dict | None:
    """Return a component dict derived from a .csproj file, or None if not a deliverable.

    Includes WinExe/Exe and Library projects under a Plugin directory path.
    Excludes support libraries (Library type outside Plugin paths).
    """
    try:
        tree = ET.parse(csproj_abs)
        root = tree.getroot()
        ns_prefix = f"{{{_MSB_NS}}}" if root.tag.startswith("{") else ""

        output_type: str | None = None
        assembly_name: str | None = None
        platform_target: str | None = None

        for pg in root.iter(f"{ns_prefix}PropertyGroup"):
            for child in pg:
                bare = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                text = (child.text or "").strip()
                if not text:
                    continue
                if bare == "OutputType":
                    output_type = text
                elif bare == "AssemblyName":
                    assembly_name = text
                elif bare in ("PlatformTarget", "Platform") and not platform_target:
                    platform_target = text

        if not output_type:
            return None

        ot_lower = output_type.lower()
        if ot_lower in ("winexe", "exe"):
            exec_type = "exe(.net)"
        elif ot_lower == "library":
            # Only include DLLs that live under a "Plugin" directory
            path_parts = [p.lower() for p in csproj_abs.replace("\\", "/").split("/")]
            if "plugin" not in path_parts:
                return None
            exec_type = "dll(.net)"
        else:
            return None

        if not assembly_name:
            assembly_name = os.path.splitext(os.path.basename(csproj_abs))[0]

        pt_lower = (platform_target or "").lower()
        if pt_lower == "x86":
            exec_arch = ["x86"]
        elif pt_lower in ("x64", "amd64"):
            exec_arch = ["x64"]
        else:
            exec_arch = ["x86", "x64"]  # AnyCPU

        ext = "exe" if exec_type == "exe(.net)" else "dll"
        return {
            "name": assembly_name,
            "exec_arch": exec_arch,
            "exec_os": ["windows"],
            "exec_type": [exec_type],
            "exec_dependency": [],
            "multi_instance": False,
            "pathname": f"{assembly_name}.{ext}",
        }
    except Exception:
        return None


def _csproj_paths_from_sln(repo_path: str) -> list[str]:
    """Return absolute paths of all .csproj/.vcxproj files referenced in any .sln."""
    paths: list[str] = []
    for sln_rel in find_files_by_extension(repo_path, [".sln"]):
        content = read_file(repo_path, sln_rel, max_bytes=131072)
        if not content:
            continue
        sln_abs_dir = os.path.dirname(os.path.join(repo_path, sln_rel.lstrip("/\\")))
        for m in _SLN_PROJECT_RE.finditer(content):
            rel = m.group(1).replace("\\", os.sep)
            abs_path = os.path.normpath(os.path.join(sln_abs_dir, rel))
            if os.path.isfile(abs_path):
                paths.append(abs_path)
    return paths


def _collect_solution_components(
    repo_path: str, build_event_tools: set[str]
) -> list[dict]:
    """Deterministically enumerate final deliverable components from solution structure.

    Walks all .csproj files referenced in .sln files, applies two filters:
    1. Self-executing build tools ($(TargetName).exe pattern) are excluded.
    2. Binaries named in build_event_tools are excluded.

    Returns components not already findable via RAG, to be merged with LLM output.
    """
    csproj_paths = _csproj_paths_from_sln(repo_path)
    if not csproj_paths:
        # Fallback: scan repo for all .csproj files
        csproj_paths = [
            os.path.join(repo_path, r.lstrip("/\\"))
            for r in find_files_by_extension(repo_path, [".csproj"])
        ]

    components: list[dict] = []
    seen: set[str] = set()

    for abs_path in csproj_paths:
        # Skip self-executing build tools (ClientBuilder, ServerSetting pattern)
        if _is_self_executing_build_tool(abs_path):
            continue

        comp = _parse_csproj_component(abs_path)
        if comp is None:
            continue

        # Skip if named in build_event_tools (explicit external tool reference)
        if comp["pathname"].lower() in build_event_tools:
            continue

        key = comp["pathname"].lower()
        if key not in seen:
            seen.add(key)
            components.append(comp)

    return components


# ---------------------------------------------------------------------------
# Builder LLM analysis (Fix C)
# When a self-executing build tool is detected, read its source code + config
# file and ask the LLM what template binary it patches and what the actual
# output filenames are.  Works regardless of config field name or schema.
# ---------------------------------------------------------------------------

# Config file extensions worth reading
_CONFIG_EXTS = frozenset([".json", ".xml", ".ini", ".cfg", ".yaml", ".yml", ".toml"])

# Source file extensions to collect from the builder project directory
_SOURCE_EXTS = frozenset([".cs", ".cpp", ".c", ".py", ".go", ".rs", ".java"])

# Executable extension pattern for multi-instance detection
_EXEC_EXT_RE = re.compile(r'\.(exe|dll|so|elf|bin)$', re.IGNORECASE)


def _flatten_dict_values(d: dict) -> list:
    """Recursively yield all scalar values from a nested dict/list structure."""
    result = []
    for v in d.values():
        if isinstance(v, dict):
            result.extend(_flatten_dict_values(v))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    result.extend(_flatten_dict_values(item))
                elif not isinstance(item, (dict, list)):
                    result.append(item)
        else:
            result.append(v)
    return result


def _is_multi_instance_config(config_content: str) -> bool:
    """Return True if any JSON config contains a top-level array-of-objects field
    where at least one object has a value ending in an executable extension.

    This deterministically detects "ClientSettings": [{...}, ...] patterns,
    which indicate the builder is designed to produce multiple binary outputs.
    The check applies regardless of the actual array length (even one element counts).
    """
    # Split concatenated config sections ("=== filename ===\n<content>")
    sections = re.split(r'=== .+ ===\n', config_content)
    for section in sections:
        section = section.strip()
        if not section:
            continue
        try:
            data = json.loads(section)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for val in data.values():
            if not (isinstance(val, list) and val and isinstance(val[0], dict)):
                continue
            # Found a top-level array of objects — check for executable filename values
            for obj in val:
                for scalar in _flatten_dict_values(obj):
                    if isinstance(scalar, str) and _EXEC_EXT_RE.search(scalar):
                        return True
    return False


def _collect_builder_source(builder_dir: str, max_total_bytes: int = 24576) -> str:
    """Read source files from the builder project directory, up to max_total_bytes."""
    parts: list[str] = []
    total = 0
    try:
        for fname in sorted(os.listdir(builder_dir)):
            if os.path.splitext(fname)[1].lower() not in _SOURCE_EXTS:
                continue
            fpath = os.path.join(builder_dir, fname)
            if not os.path.isfile(fpath):
                continue
            remaining = max_total_bytes - total
            if remaining <= 0:
                break
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as fh:
                    chunk = fh.read(remaining)
                parts.append(f"=== {fname} ===\n{chunk}")
                total += len(chunk)
            except Exception:
                pass
    except Exception:
        pass
    return "\n\n".join(parts)


def _detect_template_binary(builder_src: str) -> str | None:
    """Deterministically extract the template binary name from builder source code.

    Looks for hardcoded .exe/.dll paths passed to binary-loading calls such as
    ModuleDefMD.Load, File.ReadAllBytes, open(..., 'rb'), etc.
    Returns the basename (e.g. 'Stub.exe') or None if not found.
    """
    # Pattern: a string literal containing a .exe/.dll filename that appears
    # within a few lines of a binary-load call.
    # Strategy: find all hardcoded exe/dll string literals in the source, then
    # check whether any of them appear near a Load/ReadAllBytes call.

    # Step 1: collect candidate literal basenames (hardcoded paths).
    # Match string literals containing a path ending in .exe/.dll,
    # capturing just the filename after the last / or \ separator.
    _LITERAL_RE = re.compile(
        r'[@]?"[^"]*?[/\\]([A-Za-z0-9_\-\.]+\.(?:exe|dll))"'   # with path separator
        r'|[@]?"([A-Za-z0-9_\-\.]+\.(?:exe|dll))"',             # bare filename
        re.IGNORECASE,
    )
    _LOAD_RE = re.compile(
        r'\b(?:Load|ReadAllBytes|ReadAllText|open|fopen)\s*\(',
        re.IGNORECASE,
    )

    lines = builder_src.splitlines()
    load_line_indices: set[int] = {
        i for i, ln in enumerate(lines) if _LOAD_RE.search(ln)
    }

    for i, line in enumerate(lines):
        m = _LITERAL_RE.search(line)
        if not m:
            continue
        candidate = m.group(1) or m.group(2)  # group1: with path sep, group2: bare
        # Accept if the literal is on or within 3 lines of a Load call
        nearby = range(max(0, i - 3), min(len(lines), i + 4))
        if any(idx in load_line_indices for idx in nearby):
            return candidate
    return None


def _find_config_files_in_build_event(csproj_abs: str, repo_path: str) -> list[str]:
    """Return absolute paths of config files referenced as arguments in build events."""
    found: list[str] = []
    seen_names: set[str] = set()

    for text in _build_event_texts(csproj_abs):
        normalized = _MACRO_RE.sub("/", text)
        for token in normalized.split():
            token = token.strip('"\'').replace("\\", "/")
            ext = os.path.splitext(token)[1].lower()
            if ext not in _CONFIG_EXTS:
                continue
            fname = os.path.basename(token)
            if not fname or fname in seen_names:
                continue
            seen_names.add(fname)
            # Search entire repo for a file with this name
            for dirpath, _, filenames in os.walk(repo_path):
                for f in filenames:
                    if f.lower() == fname.lower():
                        found.append(os.path.join(dirpath, f))
    return found


_BUILDER_SYSTEM_PROMPT = """/no_think
You are a build system expert. Analyze a build tool's source code and its config file.
Determine the PRIMARY binary template→output transformation:

1. template_binary: the binary file loaded from a FIXED/HARDCODED path that serves as the
   base to be patched. Identifying marks:
   - The path is hardcoded or fixed (NOT derived from a config field like Filename).
   - It is read BEFORE any output file is written.
   - It is often in a subfolder named "Stub", "Template", "Base", etc.
   Look for: ModuleDefMD.Load(...), File.ReadAllBytes(...), open(..., 'rb'), etc.
   CRITICAL: if a file is loaded from a path that comes from a config "Filename" field,
   that is NOT the template — it is the already-written output being re-read for a second
   pass (e.g. to update version info). The template is always the FIXED-path file loaded
   in the first step, before any output is written.
   Example: stubPath = @"Stub/Stub.exe"; ModuleDefMD.Load(stubPath) → template is Stub.exe

2. output_filenames: executable files (.exe, .dll, .so, .elf) written as the final result.
   The name often comes from a config field — use the ACTUAL VALUE from the config file,
   not the field name.
   ONLY include files that are executable binaries. Do NOT include .p12, .zip, .xml,
   .json, .pem, .cer, .key, .cfg or any non-executable file.

3. multi_instance: determined SOLELY by whether the output settings field is a JSON array.
   - Array (even with one element): "ClientSettings": [{...}] → multi_instance=true
   - Single object: "ClientSettings": {...}              → multi_instance=false
   The array structure signals the builder is DESIGNED to produce multiple independently
   configured binaries per build, even if this particular config only has one entry.

4. component_name: a short human-readable display name for the output component.
   Start from the provided hint, then refine based on source code and config context.
   Use the project/solution name if it clearly applies; otherwise infer from the code.
   Examples: "AsyncRAT Client", "RAT Implant", "Loader", "Server Agent".

Return JSON only — no markdown:
{
  "template_binary": "<basename of first-loaded template binary, e.g. Stub.exe, or null>",
  "output_filenames": ["<actual output .exe/.dll filename from config>"],
  "multi_instance": <true|false>,
  "component_name": "<short descriptive name for this component>",
  "reasoning": "<one sentence explaining which code line is the template load and which is the output write>"
}

If no binary template→output transformation exists (e.g. the tool only generates config or
certificates), set template_binary=null and output_filenames=[].
Return ONLY valid JSON."""


def _get_solution_name(repo_path: str) -> str:
    """Return a clean project name from .sln filename or repo directory name."""
    _SUFFIX_RE = re.compile(
        r'[-_](C#|CSharp|Net|DotNet|Sharp)$'
        r'|[-_][vV]?\d+[\d._-]*$',
        re.IGNORECASE,
    )
    _GENERIC = frozenset(["server", "client", "main", "app", "solution", "project"])

    sln_files = find_files_by_extension(repo_path, [".sln"])
    if sln_files:
        name = os.path.splitext(os.path.basename(sln_files[0]))[0]
        name = _SUFFIX_RE.sub("", name).strip("-_ ")
        if name.lower() not in _GENERIC:
            return name

    # Fallback: repo directory name with version/suffix stripped
    dir_name = os.path.basename(repo_path.rstrip("/\\"))
    name = _SUFFIX_RE.sub("", dir_name).strip("-_ ")
    return name


# Detects ZIP creation commands in build event texts
_ZIP_DEST_RE = re.compile(
    r'-DestinationPath\s+["\']?([^\s"\']+\.zip)["\']?'    # PowerShell Compress-Archive
    r'|7z\s+a\s+["\']?([^\s"\']+\.zip)["\']?'             # 7-zip
    r'|\bzip\s+(?:-\w+\s+)*["\']?([^\s"\']+\.zip)["\']?', # Unix zip
    re.IGNORECASE,
)

# Detects file-deletion commands in build event texts
_DEL_LINE_RE = re.compile(
    r'\bdel\b|\berase\b|\brm\b|\bRemove-Item\b',
    re.IGNORECASE,
)

# Matches binary artifact filenames (used in both deletion and creation contexts)
_ARTIFACT_FNAME_RE = re.compile(
    r'\b([A-Za-z0-9_\-\.]+\.(?:exe|dll|zip|so|elf|bin))\b',
    re.IGNORECASE,
)

# Matches file creation lines beyond ZIP packaging (copy, output redirection)
_CREATE_LINE_RE = re.compile(
    r'\bCompress-Archive\b|\b7z\b|\bzip\b|\bxcopy\b|\bcopy\s|\bcp\s',
    re.IGNORECASE,
)

# Words that are exe names themselves (not file references)
_KNOWN_TOOLS = frozenset(["del.exe", "erase.exe", "rm.exe", "copy.exe", "xcopy.exe"])


def _find_zip_artifacts(repo_path: str) -> list[dict]:
    """Return component dicts for ZIP archives created by build events."""
    zip_names: set[str] = set()

    for ext in (".csproj", ".vcxproj", ".props", ".targets"):
        for rel_path in find_files_by_extension(repo_path, [ext]):
            abs_path = os.path.join(repo_path, rel_path.lstrip("/\\"))
            # Resolve $(TargetName) using the project's AssemblyName
            assembly_name = ""
            try:
                tree = ET.parse(abs_path)
                root = tree.getroot()
                ns_prefix = f"{{{_MSB_NS}}}" if root.tag.startswith("{") else ""
                for pg in root.iter(f"{ns_prefix}PropertyGroup"):
                    for child in pg:
                        bare = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if bare == "AssemblyName" and (child.text or "").strip():
                            assembly_name = child.text.strip()
                            break
                    if assembly_name:
                        break
            except Exception:
                pass
            if not assembly_name:
                assembly_name = os.path.splitext(os.path.basename(abs_path))[0]

            for text in _build_event_texts(abs_path):
                resolved = _resolve_msbuild_target_macros(text, assembly_name)
                normalized = _MACRO_RE.sub("/", resolved).replace("\\", "/")
                for m in _ZIP_DEST_RE.finditer(normalized):
                    zip_path = next(g for g in m.groups() if g)
                    basename = os.path.basename(zip_path.strip("\"' "))
                    if basename:
                        zip_names.add(basename)

    return [
        {
            "name": os.path.splitext(z)[0],
            "exec_arch": ["x86", "x64"],
            "exec_os": ["windows"],
            "exec_type": ["zip"],
            "exec_dependency": [],
            "multi_instance": False,
            "pathname": z,
        }
        for z in sorted(zip_names)
    ]


def _find_finally_deleted_artifacts(repo_path: str) -> set[str]:
    """Return lowercase basenames of artifacts deleted in build events and not recreated.

    Only marks a file as "finally deleted" if it is deleted AND not recreated (by
    Compress-Archive, 7z, zip, copy, etc.) within the same build event text block.
    Conservative: if uncertain, the file is NOT added to the returned set.
    """
    finally_deleted: set[str] = set()

    for ext in (".csproj", ".vcxproj", ".props", ".targets"):
        for rel_path in find_files_by_extension(repo_path, [ext]):
            abs_path = os.path.join(repo_path, rel_path.lstrip("/\\"))
            assembly_name = ""
            try:
                tree = ET.parse(abs_path)
                root = tree.getroot()
                ns_prefix = f"{{{_MSB_NS}}}" if root.tag.startswith("{") else ""
                for pg in root.iter(f"{ns_prefix}PropertyGroup"):
                    for child in pg:
                        bare = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if bare == "AssemblyName" and (child.text or "").strip():
                            assembly_name = child.text.strip()
                            break
                    if assembly_name:
                        break
            except Exception:
                pass
            if not assembly_name:
                assembly_name = os.path.splitext(os.path.basename(abs_path))[0]

            for text in _build_event_texts(abs_path):
                resolved = _resolve_msbuild_target_macros(text, assembly_name)
                normalized = _MACRO_RE.sub("/", resolved).replace("\\", "/")

                deleted_in_event: set[str] = set()
                created_in_event: set[str] = set()

                for line in normalized.splitlines():
                    line_s = line.strip()
                    if not line_s:
                        continue
                    if _DEL_LINE_RE.search(line_s):
                        for m in _ARTIFACT_FNAME_RE.finditer(line_s):
                            fname = m.group(1).lower()
                            if fname not in _KNOWN_TOOLS:
                                deleted_in_event.add(fname)
                    if _CREATE_LINE_RE.search(line_s):
                        for m in _ARTIFACT_FNAME_RE.finditer(line_s):
                            created_in_event.add(m.group(1).lower())

                finally_deleted |= (deleted_in_event - created_in_event)

    return finally_deleted


def _run_builder_analyses(
    repo_path: str,
    build_event_tools: set[str],
    llm: Any,
    solution_name: str = "",
) -> list[dict]:
    """For each self-executing build tool, ask LLM to identify template→output mapping.

    Returns dicts with keys: template_binary, output_filenames, multi_instance,
    component_name, csproj_abs, reasoning.
    """
    results: list[dict] = []

    csproj_paths = _csproj_paths_from_sln(repo_path)
    if not csproj_paths:
        csproj_paths = [
            os.path.join(repo_path, r.lstrip("/\\"))
            for r in find_files_by_extension(repo_path, [".csproj"])
        ]

    for csproj_abs in csproj_paths:
        if not _is_self_executing_build_tool(csproj_abs):
            continue

        builder_dir = os.path.dirname(csproj_abs)
        builder_src = _collect_builder_source(builder_dir)
        if not builder_src:
            continue

        config_paths = _find_config_files_in_build_event(csproj_abs, repo_path)
        if not config_paths:
            continue

        config_content = ""
        for cfg_path in config_paths[:2]:
            try:
                with open(cfg_path, encoding="utf-8", errors="ignore") as fh:
                    config_content += f"\n=== {os.path.basename(cfg_path)} ===\n{fh.read(4096)}"
            except Exception:
                pass
        if not config_content:
            continue

        builder_proj_name = os.path.splitext(os.path.basename(csproj_abs))[0]
        name_hint = f"{solution_name} Client" if solution_name else builder_proj_name

        try:
            response = llm.invoke([
                ("system", _BUILDER_SYSTEM_PROMPT),
                ("human", (
                    f"Solution name hint: {solution_name or '(unknown)'}\n"
                    f"Builder project: {builder_proj_name}\n"
                    f"Suggested component_name hint: \"{name_hint}\"\n\n"
                    f"Builder source:\n{builder_src}\n\nConfig file:{config_content}"
                )),
            ])
            raw = response.content.strip()
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:]).rstrip("`").strip()
            parsed = json.loads(raw)
            template = (parsed.get("template_binary") or "").strip()

            _EXEC_EXTS = frozenset([".exe", ".dll", ".so", ".dylib", ".elf", ".bin"])
            raw_outputs = parsed.get("output_filenames") or []
            outputs = [
                f for f in raw_outputs
                if f and os.path.splitext(f)[1].lower() in _EXEC_EXTS
            ]

            if template and template.lower() in {o.lower() for o in outputs}:
                template = ""

            if not template:
                template = _detect_template_binary(builder_src) or ""

            multi_instance = bool(parsed.get("multi_instance", False))
            # Deterministic override: if the config has an array-of-objects field
            # containing executable filenames, force multi_instance=true even when the LLM
            # returns false (LLMs tend to undercount multi-instance when array length=1).
            if not multi_instance and config_content:
                multi_instance = _is_multi_instance_config(config_content)
            component_name = (parsed.get("component_name") or "").strip() or name_hint

            if outputs:
                results.append({
                    "template_binary": template,
                    "output_filenames": outputs,
                    "multi_instance": multi_instance,
                    "component_name": component_name,
                    "csproj_abs": csproj_abs,
                    "reasoning": parsed.get("reasoning", ""),
                })
        except Exception:
            pass

    return results


# ---------------------------------------------------------------------------
# Fallback: direct file reads
# ---------------------------------------------------------------------------

def _fallback_context(repo_path: str, key_files: dict[str, str]) -> str:
    sections: list[str] = []
    roles = [
        "cmake", "vs_vcxproj", "vs_csproj", "vs_solution",
        "gradle", "maven", "cargo", "gomod", "makefile",
        "dockerfile", "jenkinsfile",
    ]
    for role in roles:
        if role in key_files:
            content = read_file(repo_path, key_files[role], max_bytes=4096)
            if content:
                sections.append(f"=== {key_files[role]} ===\n{content}")
    for df in find_files_by_extension(repo_path, [".dockerfile"]):
        content = read_file(repo_path, df, max_bytes=2048)
        if content:
            sections.append(f"=== {df} ===\n{content}")
    if "readme" in key_files:
        content = read_file(repo_path, key_files["readme"], max_bytes=2048)
        if content:
            sections.append(f"=== {key_files['readme']} ===\n{content}")
    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a build system expert. Identify execution components and payload info.

Return JSON:
{
  "execution_features": {
    "components": [
      {
        "name": "<component name, e.g. Server, Client, Loader DLL>",
        "exec_arch": ["x86", "x64"],
        "exec_os": ["windows"],
        "exec_type": ["<exe(.net)|dll(.net)|exe(native)|dll(native)|exe(script)|zip|other>"],
        "exec_dependency": [],
        "multi_instance": false,
        "pathname": "<output filename>"
      }
    ]
  },
  "payload_info": null,
  "reasoning": "<Explain: (1) which config entries identified each component and its name, (2) how exec_type was determined (cite specific OutputType/ConfigurationType values), (3) how exec_arch was inferred (cite Platform property), (4) why multi_instance is true/false, (5) if payload_info is populated, what code evidence indicates loader/injector behaviour. Reference specific property names and values.>"
}

For Loader / Injector type tools, populate payload_info instead of null:
{
  "payload_exec_type": ["<exe(.net)|dll(native)|shellcode|elf|powershell|...>"],
  "execution_method": ["<process-hollowing|process-herpaderping|process-doppleganging|process-ghosting|reflective-loading|.net-assembly-loading|early-bird-injection|thread-hijacking-injection|npmap-unmapviewofsection-injection|propagate-injection|userdata-injection|ewmi-injection|atom-bombing|kernelcontroltable-injection|ctrl-injection|alpc-injection|queue-user-apc-injection|custom-injection>"],
  "execution_technique_notes": ["<technique description>"],
  "payload_target_path": "<path where payload is placed or null>",
  "delivery_type": "<embedded|download|external-file>",
  "payload_transform_info": {
    "algorithm": "<RC4|AES|XOR|null>",
    "keyinfo": {"size": 128, "key_input_type": "<fixed|user-input|file>"}
  },
  "embedding_type": "<resource|overlay|data|text|null>"
}

Rules:
- components MUST contain only final deliverable binaries — binaries that are deployed or executed as the project's end product.
  EXCLUDE any binary that is invoked as an executable inside PreBuildEvent, PostBuildEvent, CustomBuildStep,
  or <Exec Command="..."> tasks of any project in the solution. Such binaries are build-time helper tools
  (e.g. encrypters, packers, resource embedders) and must NOT appear in components.
- exec_type format: "exe(.net)", "dll(.net)", "exe(native)", "dll(native)"
  MSBuild WinExe/.csproj → exe(.net); Library/.csproj → dll(.net)
  .vcxproj DLL → dll(native); .vcxproj EXE → exe(native)
- exec_arch: infer from Platform property; default ["x86","x64"] if AnyCPU or unknown
- multi_instance: true if multiple instances can run simultaneously (e.g. RAT client)
- payload_info: only for Loader/Injector; null for RAT, Implant, standalone tools
- payload_transform_info.algorithm CRITICAL RULE:
  * Look for the ACTUAL ENCRYPTION function, NOT key derivation helpers.
  * BCryptOpenAlgorithmProvider with BCRYPT_SHA256_ALGORITHM / BCRYPT_SHA1_ALGORITHM
    is SHA hashing for KEY DERIVATION — this is NOT the encryption algorithm.
  * The encryption algorithm is found in the function that transforms payload bytes:
    - A function named "RC4" or implementing KSA+PRGA loops → "RC4"
    - BCryptEncrypt with BCRYPT_AES_ALGORITHM → "AES"
    - XOR loop over payload → "XOR"
  * If no encryption is found, set algorithm to null.
- keyinfo.key_input_type: "fixed" (hardcoded key), "user-input" (key from CLI/user), "file" (key from file)
- embedding_type: "resource" (PE resource section), "overlay" (PE overlay), "data" (data section), "text" (code section)
- Return ONLY valid JSON, no markdown fences."""


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

def artifact_analyzer_node(state: AnalysisState) -> dict:
    repo_path  = state["repo_path"]
    project_id = state["project_id"]
    key_files  = state.get("key_files", {})

    context = _rag_context(project_id) or _fallback_context(repo_path, key_files)

    if not context.strip():
        return {
            "execution_features": None,
            "payload_info": None,
            "completed_nodes": ["artifact_analyzer"],
            "errors": [],
        }

    llm = get_ollama()
    messages = [
        ("system", thinking_off(_SYSTEM_PROMPT)),
        ("human", f"Build configuration:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
        if not raw:
            raise ValueError("LLM returned empty response")
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:]).rstrip("`").strip()
        data: dict[str, Any] = json.loads(raw)
        reasoning = data.pop("reasoning", "")
        output = _ArtifactAnalysisOutput(**data)
        execution_features = output.execution_features.model_dump()
        payload_info = output.payload_info.model_dump() if output.payload_info else None
    except Exception as e:
        return {
            "execution_features": None,
            "payload_info": None,
            "artifact_reasoning": "",
            "completed_nodes": ["artifact_analyzer"],
            "errors": [f"artifact_analyzer: {e}"],
        }

    # Deterministic crypto detection: override LLM algorithm if we can detect it from code.
    # LLMs commonly confuse BCrypt SHA (key derivation) with AES encryption.
    if payload_info is not None:
        # Ensure payload_transform_info exists as a dict
        if payload_info.get("payload_transform_info") is None:
            payload_info["payload_transform_info"] = {"algorithm": None, "keyinfo": None}

        # 1) Try RAG context first; 2) fallback to direct file grep
        detected = _detect_crypto_algorithm(context) or _detect_crypto_from_files(repo_path)
        if detected:
            llm_algo = (payload_info["payload_transform_info"] or {}).get("algorithm")
            if llm_algo != detected:
                payload_info["payload_transform_info"]["algorithm"] = detected
                reasoning += (
                    f"\n\n[Deterministic override] "
                    f"LLM reported algorithm='{llm_algo}' but pattern scan found '{detected}'. "
                    f"Note: BCrypt SHA-based calls are key derivation only — "
                    f"the actual payload encryption function is {detected}."
                )

    # Deterministic build-event filter: remove components whose output binary is invoked
    # as a tool in PreBuildEvent / PostBuildEvent / CustomBuildStep / <Exec> tasks.
    # These are build-time helpers, not final deliverables.
    build_event_tools = _extract_build_event_tools(repo_path, key_files)
    if build_event_tools:
        original_components = execution_features.get("components", [])
        filtered = [
            c for c in original_components
            if os.path.basename(c.get("pathname") or "").lower() not in build_event_tools
        ]
        removed = [c for c in original_components if c not in filtered]
        if removed:
            removed_names = ", ".join(c.get("pathname", c.get("name", "?")) for c in removed)
            reasoning += (
                f"\n\n[Build-event filter] Removed build-time tool(s) from components: {removed_names}. "
                f"These binaries are invoked inside build events and are not final deliverables."
            )
        execution_features["components"] = filtered

    # Deterministic solution component merge: ensure final deliverables identified from
    # .sln/.csproj structure are not missed when LLM/RAG coverage is incomplete.
    # Self-executing build tools and explicit build_event_tools are excluded here too.
    det_components = _collect_solution_components(repo_path, build_event_tools)
    if det_components:
        llm_pathnames = {
            os.path.basename(c.get("pathname") or "").lower()
            for c in execution_features.get("components", [])
        }
        added_names: list[str] = []
        for dc in det_components:
            if os.path.basename(dc["pathname"]).lower() not in llm_pathnames:
                execution_features["components"].append(dc)
                added_names.append(dc["pathname"])
        if added_names:
            reasoning += (
                f"\n\n[Solution component merge] LLM missed {len(added_names)} component(s); "
                f"added from .sln/.csproj OutputType: {', '.join(added_names)}."
            )

    # Builder LLM analysis: for each self-executing build tool, determine which binary
    # is the template stub and what the actual output filenames are. Also detects
    # multi_instance flag and a human-readable component_name via LLM.
    solution_name = _get_solution_name(repo_path)
    try:
        builder_findings = _run_builder_analyses(
            repo_path, build_event_tools, llm, solution_name=solution_name
        )
        for finding in builder_findings:
            template = (finding.get("template_binary") or "").lower()
            outputs = finding.get("output_filenames", [])
            multi_instance = finding.get("multi_instance", False)
            component_name = finding.get("component_name", "")
            if not outputs:
                continue

            # Find the template component to inherit its properties (arch, os, type)
            template_comp = next(
                (c for c in execution_features["components"]
                 if os.path.basename(c.get("pathname") or "").lower() == template),
                None,
            )

            # Remove template stub — it is not a direct deliverable
            if template:
                execution_features["components"] = [
                    c for c in execution_features["components"]
                    if os.path.basename(c.get("pathname") or "").lower() != template
                ]

            existing = {
                os.path.basename(c.get("pathname") or "").lower()
                for c in execution_features["components"]
            }

            if multi_instance:
                # Consolidate into a single component; remove any already-added individual outputs
                out_lower = {o.lower() for o in outputs}
                execution_features["components"] = [
                    c for c in execution_features["components"]
                    if os.path.basename(c.get("pathname") or "").lower() not in out_lower
                    and c.get("name") != component_name
                ]
                base_props = template_comp or {}
                execution_features["components"].append({
                    "name": component_name,
                    "exec_arch": base_props.get("exec_arch", ["x86", "x64"]),
                    "exec_os": base_props.get("exec_os", ["windows"]),
                    "exec_type": base_props.get("exec_type", ["exe(.net)"]),
                    "exec_dependency": base_props.get("exec_dependency", []),
                    "multi_instance": True,
                    "pathname": None,
                })
                note = finding.get("reasoning", "")
                reasoning += (
                    f"\n\n[Builder analysis] {os.path.basename(finding['csproj_abs'])}: "
                    f"template='{template or 'none'}' → outputs={outputs}. "
                    f"ClientSettings is array → multi_instance=True; "
                    f"added single component '{component_name}' with pathname=null. "
                    + (f"({note})" if note else "")
                )
            else:
                # Add each output as a separate component
                added_outputs: list[str] = []
                for out_file in outputs:
                    if out_file.lower() in existing:
                        continue
                    base_props = template_comp or {}
                    execution_features["components"].append({
                        "name": os.path.splitext(out_file)[0],
                        "exec_arch": base_props.get("exec_arch", ["x86", "x64"]),
                        "exec_os": base_props.get("exec_os", ["windows"]),
                        "exec_type": base_props.get("exec_type", ["exe(.net)"]),
                        "exec_dependency": base_props.get("exec_dependency", []),
                        "multi_instance": False,
                        "pathname": out_file,
                    })
                    added_outputs.append(out_file)
                    existing.add(out_file.lower())

                note = finding.get("reasoning", "")
                reasoning += (
                    f"\n\n[Builder analysis] {os.path.basename(finding['csproj_abs'])}: "
                    f"template='{template or 'none'}' → outputs={outputs}. "
                    + (f"Removed template stub; added: {', '.join(added_outputs)}. " if added_outputs else "")
                    + (f"({note})" if note else "")
                )
    except Exception as e:
        reasoning += f"\n\n[Builder analysis error] {e}"

    # ZIP artifact detection: parse PostBuildEvent for Compress-Archive / 7z / zip commands
    # and add ZIP packages as components with exec_type=["zip"].
    zip_components = _find_zip_artifacts(repo_path)
    if zip_components:
        existing_pathnames = {
            os.path.basename(c.get("pathname") or "").lower()
            for c in execution_features["components"]
        }
        added_zips: list[str] = []
        for zc in zip_components:
            if zc["pathname"].lower() not in existing_pathnames:
                execution_features["components"].append(zc)
                added_zips.append(zc["pathname"])
                existing_pathnames.add(zc["pathname"].lower())
        if added_zips:
            reasoning += (
                f"\n\n[ZIP detection] Added zip artifact(s) from build events: "
                f"{', '.join(added_zips)}."
            )

    # Deletion detection: remove components that are deleted in build events
    # and NOT recreated in the same event. Conservative — uncertain cases are kept.
    finally_deleted = _find_finally_deleted_artifacts(repo_path)
    if finally_deleted:
        original_comps = execution_features.get("components", [])
        surviving = [
            c for c in original_comps
            if os.path.basename(c.get("pathname") or "").lower() not in finally_deleted
        ]
        removed_by_del = [c for c in original_comps if c not in surviving]
        if removed_by_del:
            removed_names = ", ".join(
                c.get("pathname") or c.get("name", "?") for c in removed_by_del
            )
            execution_features["components"] = surviving
            reasoning += (
                f"\n\n[Deletion detection] Removed component(s) deleted by build events "
                f"(not recreated): {removed_names}."
            )

    return {
        "execution_features": execution_features,
        "payload_info": payload_info,
        "artifact_reasoning": reasoning,
        "completed_nodes": ["artifact_analyzer"],
        "errors": [],
    }
