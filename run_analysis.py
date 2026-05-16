#!/usr/bin/env python
"""Quick analysis runner — results are written to out/<project_id>.json.

Usage:
    python run_analysis.py /path/to/project
    python run_analysis.py /path/to/project --id my-project-id
"""

import argparse
import json
import sys
import time
from pathlib import Path

def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a source code project.")
    parser.add_argument("path", help="Path to the project directory")
    parser.add_argument(
        "--id",
        dest="project_id",
        default=None,
        help="Project ID (default: directory name)",
    )
    args = parser.parse_args()

    repo_path = Path(args.path).resolve()
    if not repo_path.is_dir():
        print(f"[ERROR] Not a directory: {repo_path}", file=sys.stderr)
        sys.exit(1)

    project_id = args.project_id or repo_path.name

    out_dir = Path(__file__).parent / "out"
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / f"{project_id}.json"

    print(f"Project : {repo_path}")
    print(f"ID      : {project_id}")
    print(f"Output  : {out_file}")
    print()

    from analysis_agent.runner import run_analysis

    start = time.time()
    print("Analyzing... (this may take 1-3 minutes)")
    result = run_analysis(str(repo_path), project_id=project_id)
    elapsed = time.time() - start

    out_file.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    # Summary to stdout
    tactics   = result.get("mitre_tactics", [])
    techniques = result.get("mitre_techniques", [])
    tags      = result.get("custom_tags", [])
    artifacts = [a.get("filename") for a in result.get("artifacts", [])]
    build_tool = result.get("build_info", {}).get("tool", "-")
    errors    = result.get("errors", [])
    langs     = result.get("language_composition", {})

    print(f"Done in {elapsed:.1f}s\n")
    print(f"  Languages  : {', '.join(f'{k}({v:.0%})' for k, v in list(langs.items())[:5])}")
    print(f"  Build tool : {build_tool}")
    print(f"  Artifacts  : {', '.join(artifacts) or '-'}")
    print(f"  Tactics    : {', '.join(tactics) or '-'}")
    print(f"  Techniques : {', '.join(techniques) or '-'}")
    print(f"  Tags       : {', '.join(tags) or '-'}")
    if errors:
        print(f"\n  Errors ({len(errors)}):")
        for e in errors:
            print(f"    - {e}")
    print(f"\nFull result → {out_file}")


if __name__ == "__main__":
    main()
