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
    """Format vocabulary into a compact string for LLM prompt injection.

    Kept intentionally short so small models (≤20B) don't get overloaded.
    """
    tactic_lines = ", ".join(f"{t['id']}({t['name']})" for t in vocab["tactics"])
    technique_lines = ", ".join(f"{t['id']}({t['name']})" for t in vocab["techniques"])
    custom_lines = ", ".join(tag["name"] for tag in vocab["custom_tags"])

    return (
        f"MITRE ATT&CK Tactics: {tactic_lines}\n"
        f"MITRE ATT&CK Techniques: {technique_lines}\n"
        f"Custom Tags: {custom_lines}"
    )
