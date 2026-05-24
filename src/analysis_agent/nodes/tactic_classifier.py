"""TacticClassifier node — MITRE ATT&CK classification + functional feature extraction.

Context source (in priority order):
  1. RAG multi-query retrieval
  2. Fallback: grep-based collection
"""

import json
import os
import re

from langchain_ollama import ChatOllama

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import grep_content, read_file


# ---------------------------------------------------------------------------
# RAG retrieval
# ---------------------------------------------------------------------------

_TACTIC_QUERIES = [
    "process start execute command powershell cmd shell script",
    "registry startup run key autostart persistence install",
    "anti analysis debug sandbox virtual machine evasion obfuscate",
    "password credential recovery harvest lsass token stealer",
    "system information enumerate process network discovery",
    "keylogger keyboard hook screen capture screenshot clipboard input",
    "tcp socket connect send receive network c2 command control",
    "RAT implant backdoor beacon malware remote administration",
    "payload loader inject reflective CLR shellcode",
]


def _rag_context(project_id: str, readme: str) -> str:
    from analysis_agent.indexer.store import get_project_collection, retrieve_multi
    col = get_project_collection(project_id)
    parts: list[str] = []

    if readme:
        parts.append(f"=== README ===\n{readme[:3000]}")

    if col and col.count() > 0:
        code_ctx = retrieve_multi(project_id, _TACTIC_QUERIES, n_per_query=3)
        if code_ctx:
            parts.append(f"=== Code Signals (RAG) ===\n{code_ctx}")

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Fallback: grep-based collection
# ---------------------------------------------------------------------------

_GREP_PATTERNS = [
    (r"WSAStartup|WSASocket|TcpClient|TcpListener|connect\s*\(|recv\s*\(|send\s*\(|HttpClient|SslStream", [".c", ".cpp", ".h", ".cs", ".go", ".rs"]),
    (r"VirtualAlloc|VirtualAllocEx|CreateRemoteThread|WriteProcessMemory|NtCreateThread|RtlCreateUserThread", [".c", ".cpp", ".h", ".cs"]),
    (r"SetWindowsHookEx|GetAsyncKeyState|keylog|KeyLogger|WH_KEYBOARD|LimeLogger", [".c", ".cpp", ".h", ".cs"]),
    (r"RegSetValueEx|RegistryKey|HKEY_CURRENT_USER|CurrentVersion\\\\Run|Startup", [".c", ".cpp", ".h", ".cs"]),
    (r"IsDebuggerPresent|CheckRemoteDebugger|Anti.Analysis|AntiDebug|MutexControl", [".c", ".cpp", ".h", ".cs"]),
    (r"lsass|credential|password|recover|stealer|harvest|token", [".c", ".cpp", ".h", ".cs"]),
    (r"Process\.Start|ProcessStartInfo|CreateProcess|ShellExecute|cmd\.exe|powershell", [".cs"]),
    (r"screenshot|CopyFromScreen|BitBlt|Bitmap\b|RemoteDesktop", [".c", ".cpp", ".h", ".cs"]),
    (r"shellcode|payload|implant|beacon|\bRAT\b|backdoor|c2\b|command.and.control", [".c", ".cpp", ".h", ".cs", ".go", ".rs", ".py", ".md"]),
    (r"Assembly\.Load|Reflection|AppDomain|Process\.Start", [".cs"]),
    (r"CLRLoad|ReflectiveDLL|LoadLibrary|GetProcAddress|inject", [".c", ".cpp", ".h"]),
]


def _fallback_context(repo_path: str, key_files: dict[str, str], readme: str) -> str:
    sections: list[str] = []
    if readme:
        sections.append(f"=== README ===\n{readme[:3000]}")

    all_hits: list[str] = []
    for pattern, exts in _GREP_PATTERNS:
        hits = grep_content(repo_path, pattern, extensions=exts, max_matches=3)
        for h in hits:
            all_hits.append(f"  {h['file']}:{h['line']}: {h['text'].strip()[:120]}")

    if all_hits:
        sections.append("=== Code Signals ===\n" + "\n".join(all_hits[:40]))

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_TEMPLATE = """You are a cybersecurity analyst. Classify this source code project.

Available vocabulary (use ONLY these IDs/names):
{vocabulary_context}

Return ONLY valid JSON (no markdown fences):
{{
  "module_category": "<RAT|C2Framework|Loader|Library|Builder>",
  "capabilities": ["<reconnaissance|initial access|execution|persistence|privilege escalation|defense evasion|credential access|discovery|lateral movement|collection|command and control|exfiltration|impact>"],
  "post_exploits": ["<camera|command and control|credential and hash harvesting|desktop control|encrypt|file upload|file download|file browser|file remove|keylogger|lateral movement|Mimikatz|mining|network and host enumeration|port scanning|privilege escalation|process creation|process execution|process termination|process listing|ransomeware|run command|screenshot>"],
  "mitre_tactics": ["TA0002", "TA0011"],
  "mitre_techniques": ["T1059", "T1056"],
  "custom_tags": ["C2 Framework", "Keylogger"],
  "reasoning": "Explain: (1) why module_category was chosen, (2) specific code signals or README passages that indicate each capability, (3) which post_exploit features were directly observed, (4) MITRE tactic/technique assignments with concrete evidence from the context."
}}

Rules:
- module_category: choose the single best fit from RAT|C2Framework|Loader|Library|Builder
  RAT = remote access trojan, implant, backdoor; Loader = loader, injector, dropper; Library = helper DLL/SDK
- capabilities: use ONLY the exact strings listed above
- post_exploits: use ONLY the exact strings listed above; empty list if not applicable
- mitre_tactics: ONLY tactics for which you see DIRECT code evidence in the context
- mitre_techniques: ONLY the 3-8 MOST PROMINENT techniques; do NOT list every possible match
- custom_tags: exact names from the Custom Tags list only
- Empty arrays are valid — do NOT fabricate IDs; quality over quantity

/no_think"""


# ---------------------------------------------------------------------------
# Deterministic MITRE enrichment
# ---------------------------------------------------------------------------

_TAG_MITRE: dict[str, tuple[list[str], list[str]]] = {
    "C2 Framework":          (["TA0011"], ["T1095", "T1071"]),
    "Keylogger":             (["TA0009"], ["T1056"]),
    "Implant":               (["TA0011", "TA0002"], ["T1219"]),
    "Injector":              (["TA0005"], ["T1055"]),
    "Loader":                (["TA0002"], ["T1129"]),
    "Dropper":               (["TA0002"], ["T1204"]),
    "Credential Harvester":  (["TA0006"], ["T1003", "T1555"]),
    "Ransomware":            (["TA0040"], ["T1486"]),
    "Rootkit":               (["TA0005", "TA0003"], ["T1027", "T1547"]),
    "Recon Tool":            (["TA0007", "TA0043"], ["T1082", "T1046"]),
    "Lateral Movement Tool": (["TA0008"], ["T1021"]),
    "Post-Exploitation":     (["TA0002", "TA0007"], ["T1059", "T1082"]),
    "Payload Delivery":      (["TA0002"], ["T1059"]),
}

_SIGNAL_MITRE: list[tuple[re.Pattern, list[str], list[str]]] = [
    (re.compile(r"powershell|cmd\.exe|Process\.Start|ProcessStartInfo|CreateProcess|ShellExecute", re.I),
     ["TA0002"], ["T1059"]),
    (re.compile(r"SetWindowsHookEx|GetAsyncKeyState|keylog|WH_KEYBOARD|LimeLogger", re.I),
     ["TA0009"], ["T1056"]),
    (re.compile(r"VirtualAlloc|CreateRemoteThread|WriteProcessMemory|NtCreateThread|RtlCreateUserThread", re.I),
     ["TA0005"], ["T1055"]),
    (re.compile(r"RegSetValueEx|RegistryKey|HKEY_CURRENT_USER|CurrentVersion.Run|Startup", re.I),
     ["TA0003"], ["T1547"]),
    (re.compile(r"IsDebuggerPresent|CheckRemoteDebugger|Anti.Analysis|AntiDebug|vmware|sandbox", re.I),
     ["TA0005"], ["T1497"]),
    (re.compile(r"runas|UAC|Token|SeTcbPrivilege|AdjustTokenPrivileges", re.I),
     ["TA0004"], ["T1548"]),
    (re.compile(r"TcpClient|Socket\b|WSAStartup|connect\s*\(|recv\s*\(|send\s*\(|SslStream", re.I),
     ["TA0011"], ["T1095"]),
    (re.compile(r"screenshot|CopyFromScreen|BitBlt|PrintWindow", re.I),
     ["TA0009"], ["T1113"]),
    (re.compile(r"lsass|credential|harvest|mimikatz|stealer", re.I),
     ["TA0006"], ["T1003"]),
    (re.compile(r"DisableDefender|impair|Remove.Malware|WindowsDefender", re.I),
     ["TA0005"], ["T1562"]),
    (re.compile(r"RegSetValue|RegOpenKey|Modify.Registry", re.I),
     ["TA0005"], ["T1112"]),
    (re.compile(r"CLRLoad|ReflectiveDLL|LoadLibrary.*inject|inject.*payload", re.I),
     ["TA0005"], ["T1055"]),
]


# Valid strict vocabularies from service VO
_VALID_MODULE_CATEGORIES = frozenset(["RAT", "C2Framework", "Loader", "Library", "Builder"])

_VALID_CAPABILITIES = frozenset([
    "reconnaissance", "initial access", "execution", "persistence",
    "privilege escalation", "defense evasion", "credential access",
    "discovery", "lateral movement", "collection", "command and control",
    "exfiltration", "impact",
])

_VALID_POST_EXPLOITS = frozenset([
    "camera", "command and control", "credential and hash harvesting",
    "desktop control", "encrypt", "file upload", "file download",
    "file browser", "file remove", "keylogger", "lateral movement",
    "Mimikatz", "mining", "network and host enumeration", "port scanning",
    "privilege escalation", "process creation", "process execution",
    "process termination", "process listing", "ransomeware", "run command",
    "screenshot",
])

# Normalize common LLM output variations to exact vocab
_POST_EXPLOIT_NORMALIZE: dict[str, str] = {
    "credential dump": "credential and hash harvesting",
    "credential harvesting": "credential and hash harvesting",
    "credentials": "credential and hash harvesting",
    "network scan": "network and host enumeration",
    "network scanning": "network and host enumeration",
    "host enumeration": "network and host enumeration",
    "lateral move": "lateral movement",
    "lateral_movement": "lateral movement",
    "process list": "process listing",
    "process kill": "process termination",
    "process terminate": "process termination",
    "ransomware": "ransomeware",
    "run cmd": "run command",
    "cmd execution": "run command",
    "shell execution": "run command",
}

# Map LLM module_category output → strict enum
_LLM_CATEGORY_NORMALIZE: dict[str, str] = {
    "RAT": "RAT",
    "C2Framework": "C2Framework",
    "C2 Framework": "C2Framework",
    "Loader": "Loader",
    "Library": "Library",
    "Builder": "Builder",
    "Implant": "RAT",
    "Backdoor": "RAT",
    "Injector": "Loader",
    "Dropper": "Loader",
    "Dropper/Loader": "Loader",
    "Credential Harvester": "RAT",
    "Ransomware": "RAT",
    "Rootkit": "RAT",
    "Recon Tool": "RAT",
    "Lateral Movement Tool": "RAT",
    "Post-Exploitation": "RAT",
    "Spyware": "RAT",
    "Other": "RAT",
}

# Deterministic category from custom_tags (first match wins) — strict enum values
_TAG_TO_CATEGORY: list[tuple[str, str]] = [
    ("C2 Framework",         "C2Framework"),
    ("Implant",              "RAT"),
    ("Loader",               "Loader"),
    ("Dropper",              "Loader"),
    ("Injector",             "Loader"),
    ("Credential Harvester", "RAT"),
    ("Ransomware",           "RAT"),
    ("Rootkit",              "RAT"),
    ("Recon Tool",           "RAT"),
    ("Lateral Movement Tool","RAT"),
    ("Post-Exploitation",    "RAT"),
    ("Keylogger",            "RAT"),
    ("Payload Delivery",     "Loader"),
]

# Maps custom_tag → CAPABILITIES (exact vocab)
_TAG_TO_CAPABILITIES: dict[str, list[str]] = {
    "C2 Framework":          ["command and control"],
    "Implant":               ["command and control", "execution"],
    "Loader":                ["execution", "defense evasion"],
    "Dropper":               ["execution"],
    "Injector":              ["defense evasion", "execution"],
    "Credential Harvester":  ["credential access"],
    "Ransomware":            ["impact"],
    "Rootkit":               ["defense evasion", "persistence"],
    "Recon Tool":            ["discovery"],
    "Lateral Movement Tool": ["lateral movement"],
    "Post-Exploitation":     ["execution", "discovery"],
    "Keylogger":             ["collection"],
    "Payload Delivery":      ["execution"],
}

# Maps custom_tag → POST_EXPLOITS (exact vocab)
_TAG_TO_POST_EXPLOITS: dict[str, list[str]] = {
    "Keylogger":             ["keylogger"],
    "C2 Framework":          ["command and control"],
    "Credential Harvester":  ["credential and hash harvesting"],
    "Recon Tool":            ["network and host enumeration"],
    "Lateral Movement Tool": ["lateral movement"],
}


def _enrich_mitre(
    tactics: list[str],
    techniques: list[str],
    custom_tags: list[str],
    context: str,
) -> tuple[list[str], list[str]]:
    t_set = set(tactics)
    te_set = set(techniques)
    for tag in custom_tags:
        if tag in _TAG_MITRE:
            new_t, new_te = _TAG_MITRE[tag]
            t_set.update(new_t)
            te_set.update(new_te)
    for pat, new_t, new_te in _SIGNAL_MITRE:
        if pat.search(context):
            t_set.update(new_t)
            te_set.update(new_te)
    return sorted(t_set), sorted(te_set)


def _derive_category(custom_tags: list[str], llm_category: str) -> str:
    for tag, category in _TAG_TO_CATEGORY:
        if tag in custom_tags:
            return category
    return _LLM_CATEGORY_NORMALIZE.get(llm_category, "RAT")


def _derive_capabilities(custom_tags: list[str], llm_caps: list[str]) -> list[str]:
    seen: set[str] = set()
    caps: list[str] = []
    for c in llm_caps:
        if c in _VALID_CAPABILITIES and c not in seen:
            seen.add(c)
            caps.append(c)
    for tag in custom_tags:
        for c in _TAG_TO_CAPABILITIES.get(tag, []):
            if c not in seen:
                seen.add(c)
                caps.append(c)
    return caps


def _derive_post_exploits(custom_tags: list[str], llm_pe: list[str]) -> list[str]:
    seen: set[str] = set()
    pe: list[str] = []
    for item in llm_pe:
        normalized = _POST_EXPLOIT_NORMALIZE.get(item.lower(), item)
        if normalized in _VALID_POST_EXPLOITS and normalized not in seen:
            seen.add(normalized)
            pe.append(normalized)
    for tag in custom_tags:
        for feat in _TAG_TO_POST_EXPLOITS.get(tag, []):
            if feat not in seen:
                seen.add(feat)
                pe.append(feat)
    return pe


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

def tactic_classifier_node(state: AnalysisState) -> dict:
    repo_path          = state["repo_path"]
    project_id         = state["project_id"]
    key_files          = state.get("key_files", {})
    readme             = state.get("readme_content", "")
    vocabulary_context = state.get("vocabulary_context", "")

    from analysis_agent.indexer.store import get_project_collection
    col = get_project_collection(project_id)

    if col and col.count() > 0:
        context = _rag_context(project_id, readme)
    else:
        context = _fallback_context(repo_path, key_files, readme)

    if not context.strip():
        return {
            "module_category": "Other",
            "capabilities": [],
            "post_exploits": [],
            "mitre_tactics": [], "mitre_techniques": [], "custom_tags": [],
            "completed_nodes": ["tactic_classifier"], "errors": [],
        }

    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(vocabulary_context=vocabulary_context)
    llm = ChatOllama(
        model=os.getenv("OLLAMA_MODEL", "gpt-oss:20b"),
        temperature=0,
        format="json",
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        num_predict=4096,
        num_ctx=8192,
    )
    messages = [
        ("system", system_prompt),
        ("human", f"Project context:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
        if not raw:
            raise ValueError("LLM returned empty response")
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:]).rstrip("`").strip()
        data = json.loads(raw)
        mitre_tactics     = data.get("mitre_tactics", [])
        mitre_techniques  = data.get("mitre_techniques", [])
        custom_tags       = data.get("custom_tags", [])
        llm_category      = data.get("module_category", "")
        llm_capabilities  = data.get("capabilities", [])
        llm_post_exploits = data.get("post_exploits", [])
        tactic_reasoning  = data.get("reasoning", "")
    except Exception as e:
        mitre_tactics, mitre_techniques = _enrich_mitre([], [], [], context)
        custom_tags = []
        llm_category, llm_capabilities, llm_post_exploits = "", [], []
        return {
            "module_category":  _derive_category(custom_tags, llm_category),
            "capabilities":     _derive_capabilities(custom_tags, llm_capabilities),
            "post_exploits":    _derive_post_exploits(custom_tags, llm_post_exploits),
            "mitre_tactics":    mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "custom_tags":      custom_tags,
            "tactic_reasoning": f"(LLM failed — deterministic signal enrichment used) {e}",
            "completed_nodes":  ["tactic_classifier"],
            "errors":           [f"tactic_classifier (LLM failed, used signal enrichment): {e}"],
        }

    mitre_tactics, mitre_techniques = _enrich_mitre(
        mitre_tactics, mitre_techniques, custom_tags, context
    )

    return {
        "module_category":  _derive_category(custom_tags, llm_category),
        "capabilities":     _derive_capabilities(custom_tags, llm_capabilities),
        "post_exploits":    _derive_post_exploits(custom_tags, llm_post_exploits),
        "mitre_tactics":    mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "custom_tags":      custom_tags,
        "tactic_reasoning": tactic_reasoning,
        "completed_nodes":  ["tactic_classifier"],
        "errors":           [],
    }
