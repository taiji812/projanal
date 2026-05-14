"""TacticClassifier node — classifies the tool against MITRE ATT&CK and custom vocabulary."""
import json

from langchain_ollama import ChatOllama

from analysis_agent.state import AnalysisState
from analysis_agent.tools.filesystem import grep_content, read_file

_SYSTEM_PROMPT_TEMPLATE = """You are a cybersecurity analyst specializing in offensive security tools and red teaming.

Classify the given source code project against the following vocabulary.

{vocabulary_context}

Based on the code context provided, identify:
1. Which MITRE ATT&CK tactics (TA####) apply
2. Which MITRE ATT&CK techniques (T####) apply
3. Which custom tags apply

Return ONLY valid JSON in this exact format (no markdown fences):
{{
  "mitre_tactics": ["TA0002", "TA0005"],
  "mitre_techniques": ["T1059", "T1055"],
  "custom_tags": ["C2 Framework", "Implant"],
  "reasoning": "One sentence summary of what this tool does"
}}

Rules:
- Only include IDs/names that appear in the vocabulary above
- Be precise — only include tactics/techniques clearly evidenced by the code
- mitre_techniques: list specific sub-techniques if applicable (e.g. T1059.001 for PowerShell)
- custom_tags: use exact names from the custom vocabulary"""


def _collect_classification_context(repo_path: str, key_files: dict[str, str], readme: str) -> str:
    sections: list[str] = []

    # README is highest signal
    if readme:
        sections.append(f"=== README ===\n{readme[:4096]}")

    # Jenkinsfile or CI hints
    for role in ("jenkinsfile",):
        if role in key_files:
            content = read_file(repo_path, key_files[role], max_bytes=1024)
            if content:
                sections.append(f"=== {key_files[role]} ===\n{content}")

    # Grep for C2 / network / injection patterns
    signal_patterns = [
        (r"(?:socket|connect|recv|send|WSAStartup|WinHttp)", [".c", ".cpp", ".h", ".cs", ".go", ".rs"]),
        (r"(?:VirtualAlloc|CreateRemoteThread|WriteProcessMemory|NtCreateThread)", [".c", ".cpp", ".h", ".cs"]),
        (r"(?:shellcode|payload|implant|beacon|agent|c2|c&c|command.and.control)", [".c", ".cpp", ".h", ".cs", ".go", ".rs", ".py"]),
        (r"(?:inject|hook|patch|bypass|evade|obfuscat)", [".c", ".cpp", ".h", ".cs", ".go", ".rs"]),
        (r"(?:keylog|screenshot|screencap|clipboard)", [".c", ".cpp", ".h", ".cs"]),
        (r"(?:lsass|mimikatz|credential|password|hash|token)", [".c", ".cpp", ".h", ".cs"]),
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
