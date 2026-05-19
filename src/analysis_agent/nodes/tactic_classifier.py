"""TacticClassifier node — MITRE ATT&CK and custom tag classification.

Context source (in priority order):
  1. RAG multi-query retrieval (one query per tactic category)
  2. Fallback: grep-based collection
"""

import json
import os
import re

from langchain_ollama import ChatOllama

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import grep_content, read_file

# ---------------------------------------------------------------------------
# RAG retrieval (primary path)
# ---------------------------------------------------------------------------

# Queries aligned to major tactic categories — cast a wide, diverse net
_TACTIC_QUERIES = [
    # TA0002 Execution
    "process start execute command powershell cmd shell script",
    # TA0003 Persistence
    "registry startup run key autostart persistence install",
    # TA0005 Defense Evasion / TA0497 Sandbox
    "anti analysis debug sandbox virtual machine evasion obfuscate",
    # TA0006 Credential Access
    "password credential recovery harvest lsass token stealer",
    # TA0007 Discovery
    "system information enumerate process network discovery",
    # TA0009 Collection / Keylogger / Screenshot
    "keylogger keyboard hook screen capture screenshot clipboard input",
    # TA0010 Exfiltration / TA0011 C2
    "tcp socket connect send receive network c2 command control",
    # Generic red team
    "RAT implant backdoor beacon malware remote administration",
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
# Fallback: grep-based collection (used when index not available)
# ---------------------------------------------------------------------------

_GREP_PATTERNS = [
    # Network / C2
    (r"WSAStartup|WSASocket|TcpClient|TcpListener|connect\s*\(|recv\s*\(|send\s*\(|HttpClient|SslStream", [".c", ".cpp", ".h", ".cs", ".go", ".rs"]),
    # Process injection
    (r"VirtualAlloc|VirtualAllocEx|CreateRemoteThread|WriteProcessMemory|NtCreateThread|RtlCreateUserThread", [".c", ".cpp", ".h", ".cs"]),
    # Keylogger / input capture
    (r"SetWindowsHookEx|GetAsyncKeyState|keylog|KeyLogger|WH_KEYBOARD|LimeLogger", [".c", ".cpp", ".h", ".cs"]),
    # Persistence
    (r"RegSetValueEx|RegistryKey|HKEY_CURRENT_USER|CurrentVersion\\\\Run|Startup", [".c", ".cpp", ".h", ".cs"]),
    # Defense evasion
    (r"IsDebuggerPresent|CheckRemoteDebugger|Anti.Analysis|AntiDebug|MutexControl", [".c", ".cpp", ".h", ".cs"]),
    # Credential access
    (r"lsass|credential|password|recover|stealer|harvest|token", [".c", ".cpp", ".h", ".cs"]),
    # Execution
    (r"Process\.Start|ProcessStartInfo|CreateProcess|ShellExecute|cmd\.exe|powershell", [".cs"]),
    # Screenshot / collection
    (r"screenshot|CopyFromScreen|BitBlt|Bitmap\b|RemoteDesktop", [".c", ".cpp", ".h", ".cs"]),
    # Generic red team keywords
    (r"shellcode|payload|implant|beacon|\bRAT\b|backdoor|c2\b|command.and.control", [".c", ".cpp", ".h", ".cs", ".go", ".rs", ".py", ".md"]),
    # C# / .NET specific
    (r"Assembly\.Load|Reflection|AppDomain|Process\.Start", [".cs"]),
]


def _fallback_context(repo_path: str, key_files: dict[str, str], readme: str) -> str:
    sections: list[str] = []
    if readme:
        sections.append(f"=== README ===\n{readme[:3000]}")

    all_hits: list[str] = []
    for pattern, exts in _GREP_PATTERNS:
        hits = grep_content(repo_path, pattern, extensions=exts, max_matches=3)
        for h in hits:
            line = h["text"].strip()[:120]
            all_hits.append(f"  {h['file']}:{h['line']}: {line}")

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
  "mitre_tactics": ["TA0002", "TA0011"],
  "mitre_techniques": ["T1059", "T1056"],
  "custom_tags": ["C2 Framework", "Keylogger"],
  "reasoning": "One sentence describing what this tool does"
}}

Rules:
- Include a tactic only if the project clearly implements that functionality
- Include a technique only if specific code evidence exists
- custom_tags: exact names from the Custom Tags list only
- Empty arrays are valid if no match is found — do NOT fabricate IDs

/no_think"""


# ---------------------------------------------------------------------------
# Deterministic MITRE enrichment (post-LLM, fills gaps without adding tokens)
# ---------------------------------------------------------------------------

# Maps custom_tags → (tactics, techniques) guaranteed by definition
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
}

# Maps code signal patterns → (tactics, techniques)
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
]


def _enrich_mitre(
    tactics: list[str],
    techniques: list[str],
    custom_tags: list[str],
    context: str,
) -> tuple[list[str], list[str]]:
    """Add deterministic MITRE mappings from custom_tags and code signals."""
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
        mitre_tactics    = data.get("mitre_tactics", [])
        mitre_techniques = data.get("mitre_techniques", [])
        custom_tags      = data.get("custom_tags", [])
    except Exception as e:
        # LLM failed — still run deterministic enrichment on context alone
        mitre_tactics, mitre_techniques, custom_tags = [], [], []
        mitre_tactics, mitre_techniques = _enrich_mitre([], [], [], context)
        return {
            "mitre_tactics":   mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "custom_tags":     custom_tags,
            "completed_nodes": ["tactic_classifier"],
            "errors":          [f"tactic_classifier (LLM failed, used signal enrichment): {e}"],
        }

    mitre_tactics, mitre_techniques = _enrich_mitre(
        mitre_tactics, mitre_techniques, custom_tags, context
    )

    return {
        "mitre_tactics":    mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "custom_tags":      custom_tags,
        "completed_nodes":  ["tactic_classifier"],
        "errors":           [],
    }
