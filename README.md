# ProjectAnalysisAgent

A multi-agent system that analyzes source code projects and extracts features, build info, artifacts, and MITRE ATT&CK tactics/techniques as structured JSON.

## Overview

```
START → file_explorer → [language_analyzer, build_analyzer, artifact_analyzer, tactic_classifier] → aggregator → END
```

- `file_explorer` runs first (downstream nodes depend on `key_files` and `file_tree`)
- Four analysis nodes run in parallel via LangGraph fan-out
- `aggregator` merges results after all parallel nodes complete

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com) running locally or via network with the `gpt-oss:20b` model

## Installation

```bash
pip install -e .
```

## Usage

### CLI

```bash
analyze /path/to/project --id my-project --output result.json
```

### REST API

```bash
python -m analysis_agent.api.routes
```

| Endpoint | Description |
|---|---|
| `POST /analyze/path` | Analyze a path on the server filesystem |
| `POST /analyze/upload` | Upload and analyze a zip archive |
| `GET /analyze/{job_id}` | Poll analysis job status |

### Python

```python
from analysis_agent.runner import run_analysis

result = run_analysis("/path/to/project", project_id="my-project")
```

## Output Schema

```json
{
  "project_id": "string",
  "analyzed_at": "ISO8601",
  "language_composition": { "C++": 0.61, "C/C++ Header": 0.19 },
  "mitre_tactics": ["TA0002", "TA0011"],
  "mitre_techniques": ["T1059", "T1056"],
  "custom_tags": ["C2 Framework", "Keylogger"],
  "build_info": {
    "tool": "MSBuild",
    "tool_path": "",
    "commands": ["MSBuild.exe Lilith.sln /p:Configuration=Release"],
    "environment": "windows",
    "parameters": [
      {
        "name": "Configuration",
        "type": "choice",
        "default": "Release",
        "choices": ["Debug", "Release"],
        "description": "...",
        "source": "Lilith.sln"
      }
    ],
    "notes": "..."
  },
  "artifacts": [
    {
      "filename": "Lilith.exe",
      "output_path": "Release\\x64",
      "artifact_type": "exe",
      "description": "..."
    }
  ],
  "errors": []
}
```

## Configuration

### Ollama endpoint

Set the `OLLAMA_BASE_URL` environment variable (default: `http://localhost:11434`):

```bash
export OLLAMA_BASE_URL=http://ollama-service:11434
```

### Vocabulary

- `config/vocabulary/mitre_attack_enterprise.yaml` — MITRE ATT&CK Enterprise v15 tactics and techniques
- `config/vocabulary/custom.yaml` — custom tags (C2 Framework, Implant, etc.)

To add a custom tag:

```yaml
# config/vocabulary/custom.yaml
custom_tags:
  - name: "My Custom Tag"
    description: "Description"
```

## Extending

### Adding a new analysis node

1. Create `src/analysis_agent/nodes/my_node.py`
2. Implement `def my_node(state: AnalysisState) -> dict` — always include `"completed_nodes": ["my_node"]` and `"errors": []` in the return value
3. Add the output field to `AnalysisState` in `state.py`
4. Register the node and edges in `graph.py`:

```python
g.add_node("my_node", my_node)
g.add_edge("file_explorer", "my_node")
g.add_edge("my_node", "aggregator")
```

## Deployment (sidecar pattern)

Run alongside an existing service pod sharing the same volume:

```yaml
volumes:
  - name: workspace
    emptyDir: {}
containers:
  - name: main-service
    volumeMounts:
      - name: workspace
        mountPath: /workspace
  - name: analysis-agent
    image: analysis-agent:latest
    volumeMounts:
      - name: workspace
        mountPath: /workspace
    env:
      - name: OLLAMA_BASE_URL
        value: http://ollama-service:11434
```

Trigger analysis from the main service:

```bash
analyze /workspace/{repo-id}/ --id {project-id}
```

### Docker

```bash
docker build -t analysis-agent .
docker run -e OLLAMA_BASE_URL=http://host.docker.internal:11434 -p 8080:8080 analysis-agent
```

## Tech Stack

- **LLM**: Ollama (`gpt-oss:20b`)
- **Framework**: LangChain + LangGraph (StateGraph)
- **Interface**: Typer CLI + FastAPI REST
- **Output**: JSON (MongoDB schema compatible)
