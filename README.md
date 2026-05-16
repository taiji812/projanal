# ProjectAnalysisAgent

A multi-agent system that analyzes source code projects and extracts features, build info, artifacts, and MITRE ATT&CK tactics/techniques as structured JSON.

## Overview

```
START → file_explorer → index_builder → [language_analyzer, build_analyzer, artifact_analyzer, tactic_classifier] → aggregator → END
```

- `file_explorer` runs first (downstream nodes depend on `key_files` and `file_tree`)
- `index_builder` parses source files with tree-sitter and indexes them into a per-project ChromaDB collection
- Four analysis nodes run in parallel via LangGraph fan-out, each using RAG retrieval as the primary context source
- `aggregator` merges results after all parallel nodes complete

## Requirements

- Python 3.11+
- [Ollama](https://ollama.com) running locally or via network with the `gpt-oss:20b` model

## Installation

```bash
pip install -e .
```

## Usage

### Script (가장 간단)

```bash
# 프로젝트 ID는 폴더명으로 자동 설정
python run_analysis.py /path/to/project

# ID 직접 지정
python run_analysis.py /path/to/project --id my-project
```

결과는 `out/<project_id>.json`에 저장되고 터미널에 요약이 출력됩니다.

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

## RAG 인덱싱

`index_builder` 노드가 분석 전에 프로젝트를 자동 인덱싱합니다.

- **청킹 전략**: tree-sitter AST 기반 (함수/클래스 단위) — C#, C/C++, Go, Rust, Java, Python, JS, TS
  - MSBuild XML (`.csproj`/`.vcxproj`): PropertyGroup/ItemGroup 섹션
  - `.sln`: 프로젝트 참조 목록
  - Makefile: 타겟 블록
  - 그 외: 슬라이딩 윈도우 (60줄, 10줄 오버랩)
- **임베딩**: `ANALYSIS_EMBED_MODEL` 환경변수 설정 시 Ollama 임베딩 모델 사용, 미설정 시 `all-MiniLM-L6-v2` (초기 실행 시 ~90MB 자동 다운로드)
- **벡터 스토어**: ChromaDB EphemeralClient (프로세스 내 메모리, 프로젝트별 컬렉션)

```bash
# Ollama 임베딩 사용 시
export ANALYSIS_EMBED_MODEL=nomic-embed-text
```

## MITRE 분류 방식

`tactic_classifier`는 두 단계로 MITRE ATT&CK ID를 결정합니다.

1. **LLM** (짧은 프롬프트): RAG 컨텍스트를 보고 `custom_tags` 반환
2. **`_enrich_mitre()`** (결정론적): 태그 룩업 + 코드 시그널 패턴 매칭으로 tactics/techniques 추가
   - LLM 실패 시에도 컨텍스트 기반 분류 제공

MITRE 매핑 규칙 추가/수정: `src/analysis_agent/nodes/tactic_classifier.py`의 `_TAG_MITRE`, `_SIGNAL_MITRE`.

## Tech Stack

- **LLM**: Ollama (`gpt-oss:20b`)
- **Framework**: LangChain + LangGraph (StateGraph)
- **Indexing**: tree-sitter 0.25 + ChromaDB
- **Interface**: Typer CLI + FastAPI REST
- **Output**: JSON (MongoDB schema compatible)
