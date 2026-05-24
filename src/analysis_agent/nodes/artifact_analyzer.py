"""ArtifactAnalyzer node — infers execution components and optional payload info.

Context source (in priority order):
  1. RAG retrieval from ChromaDB
  2. Fallback: direct file reads
"""

import json
import os
import re
from typing import Any, Optional

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field, model_validator

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
]


def _rag_context(project_id: str) -> str:
    from analysis_agent.indexer.store import get_project_collection, retrieve_multi
    col = get_project_collection(project_id)
    if col is None or col.count() == 0:
        return ""
    return retrieve_multi(project_id, _ARTIFACT_QUERIES, n_per_query=4)


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
- Return ONLY valid JSON, no markdown fences.

/no_think"""


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

    llm = ChatOllama(
        model=os.getenv("OLLAMA_MODEL", "gpt-oss:20b"),
        temperature=0,
        format="json",
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        num_predict=4096,
        num_ctx=8192,
    )
    messages = [
        ("system", _SYSTEM_PROMPT),
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

    return {
        "execution_features": execution_features,
        "payload_info": payload_info,
        "artifact_reasoning": reasoning,
        "completed_nodes": ["artifact_analyzer"],
        "errors": [],
    }
