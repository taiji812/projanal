from pathlib import Path

import yaml

_CONFIG_DIR = Path(__file__).parent.parent.parent.parent / "config" / "vocabulary"


def load_vocabulary(custom_path: str | None = None) -> dict:
    """Load MITRE ATT&CK Enterprise + custom vocabulary."""
    mitre_path = _CONFIG_DIR / "mitre_attack_enterprise.yaml"
    with open(mitre_path, "r") as f:
        mitre = yaml.safe_load(f)

    custom_file = Path(custom_path) if custom_path else _CONFIG_DIR / "custom.yaml"
    custom: dict = {"custom_tags": []}
    if custom_file.exists():
        with open(custom_file, "r") as f:
            custom = yaml.safe_load(f) or {}

    return {
        "tactics": mitre.get("tactics", []),
        "techniques": mitre.get("techniques", []),
        "custom_tags": custom.get("custom_tags", []),
    }


def format_vocabulary_context(vocab: dict) -> str:
    """Format vocabulary into a compact string for LLM system prompt injection."""
    lines = ["=== MITRE ATT&CK Enterprise Tactics ==="]
    for t in vocab["tactics"]:
        lines.append(f"  {t['id']} - {t['name']}: {t['description']}")

    lines.append("\n=== MITRE ATT&CK Enterprise Techniques (subset) ===")
    for t in vocab["techniques"]:
        lines.append(f"  {t['id']} - {t['name']} (tactic: {t['tactic']})")

    lines.append("\n=== Custom Tags ===")
    for tag in vocab["custom_tags"]:
        lines.append(f"  {tag['name']}: {tag['description']}")

    return "\n".join(lines)
