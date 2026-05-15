"""TacticClassifier node — classifies the tool against MITRE ATT&CK and custom vocabulary."""
import json

from langchain_ollama import ChatOllama

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import grep_content, read_file

_SYSTEM_PROMPT_TEMPLATE = """You are a cybersecurity analyst. Analyze the provided source code project and classify it.

Available vocabulary (use ONLY these IDs/names):
{vocabulary_context}

Return ONLY valid JSON (no markdown fences, no extra keys):
{{
  "mitre_tactics": ["TA0002", "TA0011"],
  "mitre_techniques": ["T1059", "T1056"],
  "custom_tags": ["C2 Framework", "Keylogger"],
  "reasoning": "One sentence describing what this tool does"
}}

Classification rules:
- Include a tactic if the project clearly implements functionality belonging to it
- Include a technique if specific code evidence exists (function names, API calls, file names)
- custom_tags: pick from the Custom Tags list only; use exact names
- If no match exists, return empty arrays — do NOT fabricate IDs"""


def _collect_classification_context(repo_path: str, key_files: dict[str, str], readme: str) -> str:
    sections: list[str] = []

    # README is highest signal — use up to 6KB
    if readme:
        sections.append(f"=== README ===\n{readme[:6144]}")

    # Jenkinsfile or CI hints
    for role in ("jenkinsfile",):
        if role in key_files:
            content = read_file(repo_path, key_files[role], max_bytes=1024)
            if content:
                sections.append(f"=== {key_files[role]} ===\n{content}")

    # Grep for C2 / network / injection / persistence / evasion patterns
    signal_patterns = [
        # Network / C2
        (r"(?:WSAStartup|WSASocket|socket\s*\(|connect\s*\(|recv\s*\(|send\s*\(|WinHttp|HttpSend|URLDownload)", [".c", ".cpp", ".h", ".cs", ".go", ".rs"]),
        # Process injection / code execution
        (r"(?:VirtualAlloc|VirtualAllocEx|CreateRemoteThread|WriteProcessMemory|NtCreateThread|RtlCreateUserThread|NtUnmapView)", [".c", ".cpp", ".h", ".cs"]),
        # Keylogger / input capture
        (r"(?:SetWindowsHookEx|GetAsyncKeyState|GetKeyState|keylog|KeyLogger|WH_KEYBOARD)", [".c", ".cpp", ".h", ".cs"]),
        # Persistence
        (r"(?:RegSetValueEx|HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run|StartupFolder|Startup)", [".c", ".cpp", ".h", ".cs"]),
        # Defense evasion
        (r"(?:inject|hook|patch|bypass|evade|obfuscat|IsDebuggerPresent|CheckRemoteDebugger)", [".c", ".cpp", ".h", ".cs", ".go", ".rs"]),
        # Credential / privilege
        (r"(?:lsass|mimikatz|credential|password|hash|token|privilege|SeDebug)", [".c", ".cpp", ".h", ".cs"]),
        # Execution via scripting
        (r"(?:PowerShell|WScript|ShellExecute|CreateProcess|cmd\.exe|WMI|IWbem)", [".c", ".cpp", ".h", ".cs"]),
        # Generic red team keywords in any text file
        (r"(?:shellcode|payload|implant|beacon|agent|c2\b|RAT\b|backdoor|rootkit)", [".c", ".cpp", ".h", ".cs", ".go", ".rs", ".py", ".md", ".txt"]),
    ]

    all_hits: list[str] = []
    for pattern, exts in signal_patterns:
        hits = grep_content(repo_path, pattern, extensions=exts, max_matches=8)
        for h in hits:
            all_hits.append(f"  {h['file']}:{h['line']}: {h['text']}")

    if all_hits:
        sections.append("=== Code Signals ===\n" + "\n".join(all_hits[:60]))

    return "\n\n".join(sections)


def tactic_classifier_node(state: AnalysisState) -> dict:
    repo_path = state["repo_path"]
    key_files = state.get("key_files", {})
    readme = state.get("readme_content", "")
    vocabulary_context = state.get("vocabulary_context", "")

    context = _collect_classification_context(repo_path, key_files, readme)
    if not context.strip():
        return {
            "mitre_tactics": [],
            "mitre_techniques": [],
            "custom_tags": [],
            "completed_nodes": ["tactic_classifier"],
            "errors": [],
        }

    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(vocabulary_context=vocabulary_context)
    llm = ChatOllama(model="gpt-oss:20b", temperature=0, format="json")

    messages = [
        ("system", system_prompt),
        ("human", f"Source code project context:\n\n{context}"),
    ]

    try:
        response = llm.invoke(messages)
        raw = response.content.strip()
        data = json.loads(raw)
        mitre_tactics = data.get("mitre_tactics", [])
        mitre_techniques = data.get("mitre_techniques", [])
        custom_tags = data.get("custom_tags", [])
    except Exception as e:
        return {
            "mitre_tactics": [],
            "mitre_techniques": [],
            "custom_tags": [],
            "completed_nodes": ["tactic_classifier"],
            "errors": [f"tactic_classifier: {e}"],
        }

    return {
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "custom_tags": custom_tags,
        "completed_nodes": ["tactic_classifier"],
        "errors": [],
    }
