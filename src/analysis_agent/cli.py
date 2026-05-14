"""CLI entry point — typer-based."""
import json
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(name="analyze", add_completion=False, help="Source code analysis agent")


@app.command()
def analyze(
    repo_path: str = typer.Argument(..., help="Path to the extracted project directory"),
    project_id: str = typer.Option("", "--id", "-i", help="Project identifier"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON result to file"),
    custom_vocab: Optional[Path] = typer.Option(None, "--vocab", help="Custom vocabulary YAML file"),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output"),
):
    """Analyze a source code project and output structured JSON."""
    from analysis_agent.runner import run_analysis

    typer.echo(f"Analyzing: {repo_path}", err=True)
    try:
        result = run_analysis(
            repo_path=repo_path,
            project_id=project_id,
            custom_vocabulary_path=str(custom_vocab) if custom_vocab else None,
        )
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Unexpected error: {e}", err=True)
        raise typer.Exit(2)

    indent = 2 if pretty else None
    json_output = json.dumps(result, indent=indent, ensure_ascii=False)

    if output:
        output.write_text(json_output, encoding="utf-8")
        typer.echo(f"Result written to {output}", err=True)
    else:
        typer.echo(json_output)


if __name__ == "__main__":
    app()
