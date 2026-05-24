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

> **의존성은 Docker 이미지 안에만 설치되어 있습니다.** 로컬 Python 환경 없이 아래 Docker 방법으로 테스트하세요.

### 0. 환경 설정

```bash
cp .env.example .env
# .env 편집: OLLAMA_BASE_URL, OLLAMA_MODEL, WORKSPACE_PATH 등 설정
```

### 0-1. 이미지 빌드 (코드 변경 후 1회)

```bash
docker compose build
# 또는
docker build -t analysis-agent .
```

---

### 방법 0 — Docker Compose (권장)

`.env` 파일로 환경변수를 관리하고 docker compose로 실행합니다.

**CLI 일회성 분석:**

```bash
# .env의 WORKSPACE_PATH 사용
docker compose run --rm cli /workspace --id my-project --output /out/my-project.json

# 경로를 직접 지정할 경우
WORKSPACE_PATH=/path/to/project docker compose run --rm cli /workspace --id my-project --output /out/my-project.json
```

**REST API 서버:**

```bash
docker compose up api          # 포그라운드
docker compose up -d api       # 백그라운드
docker compose down            # 종료
```

---

### 방법 1 — CLI (가장 간단, 일회성 테스트)

분석할 폴더를 컨테이너에 마운트하고 `analyze` CLI를 직접 실행합니다.

```bash
# 결과를 터미널에 출력 (JSON)
docker run --rm \
  -v /path/to/project:/workspace \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  --entrypoint analyze \
  analysis-agent /workspace --id my-project

# 결과를 로컬 out/ 디렉토리에 파일로 저장
mkdir -p out
docker run --rm \
  -v /path/to/project:/workspace \
  -v $(pwd)/out:/out \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  --entrypoint analyze \
  analysis-agent /workspace --id my-project --output /out/my-project.json
```

---

### 방법 2 — REST API · 볼륨 마운트 (반복 테스트에 유리)

서버를 한 번 띄우고 `curl`로 여러 프로젝트를 순서대로 분석합니다.

**서버 시작**

```bash
docker run -d --name analysis-api \
  -p 8080:8080 \
  -v /path/to/projects:/projects \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  analysis-agent
```

**분석 요청 (동기 응답, 1–3분 소요)**

```bash
curl -s -X POST http://localhost:8080/analyze/path \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/projects/MyProject", "project_id": "my-project"}' \
  | python3 -m json.tool
```

**서버 종료**

```bash
docker stop analysis-api && docker rm analysis-api
```

---

### 방법 3 — REST API · zip 업로드 (볼륨 마운트 없이)

```bash
# 서버 시작 (볼륨 불필요)
docker run -d --name analysis-api \
  -p 8080:8080 \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  analysis-agent

# 프로젝트 압축 후 업로드 (비동기, job_id 반환)
zip -r my-project.zip /path/to/project
curl -s -X POST http://localhost:8080/analyze/upload \
  -F "file=@my-project.zip"
# → {"job_id": "xxxxxxxx-...", "status": "accepted"}

# 결과 폴링 (completed 될 때까지 반복)
curl -s http://localhost:8080/analyze/<job_id> | python3 -m json.tool

docker stop analysis-api && docker rm analysis-api
```

---

### Python (의존성 설치된 환경)

```python
from analysis_agent.runner import run_analysis

result = run_analysis("/path/to/project", project_id="my-project")
```

## Output Schema

`ModuleProperty` 포맷 (`src/analysis_agent/schema.py`의 Pydantic 모델로 검증):

```json
{
  "module_name": "string",
  "module_category": "RAT | Loader | Implant | Dropper | Injector | Credential Harvester | ...",
  "module_form": {
    "form_type": "sourcecode",
    "source_language": ["C#"],
    "has_submodule": false
  },
  "functional_features": {
    "capabilities": ["command and control", "execution"],
    "post_exploits": ["keylogger", "file upload", "file download", "run command"]
  },
  "build_features": {
    "build_tool": "msbuild_dotnet | msbuild | cmake | make | cargo | go | ...",
    "no_concurrent_build": false,
    "build_tool_args": "Lilith.sln /p:Configuration=${msbuild_cfg} /p:Platform=${platform}",
    "build_params": [
      {
        "param_type": "string | choice | object | boolean",
        "param_title": "빌드 설정 옵션",
        "param_name": "msbuild_cfg",
        "param_description": "빌드 설정 옵션",
        "param_default": "Release",
        "choice_list": ["Release", "Debug"]
      }
    ],
    "build_env": { "build_env_os": "windows | linux | macos | cross" },
    "artifacts_archive": "**/*.exe",
    "build_dependencies": []
  },
  "execution_features": {
    "components": [
      {
        "name": "Lilith Server",
        "exec_arch": ["x86", "x64"],
        "exec_os": ["windows"],
        "exec_type": ["exe(native)"],
        "exec_dependency": [],
        "multi_instance": false,
        "pathname": "Server.exe"
      }
    ]
  },
  "payload_info": null,
  "mitre_tactics": ["TA0002", "TA0011"],
  "mitre_techniques": ["T1059", "T1056"],
  "analyzed_at": "ISO8601",
  "errors": []
}
```

`payload_info`는 Loader/Injector 타입에만 채워집니다:

```json
"payload_info": {
  "payload_exec_type": ["dll(native)"],
  "execution_method": ["reflective-loading"],
  "execution_technique_notes": ["CLR Loading"],
  "payload_target_path": "Payload\\",
  "delivery_type": "external-file",
  "payload_transform_info": {
    "algorithm": "RC4",
    "keyinfo": { "size": 128, "key_input_type": "user-input" }
  },
  "embedding_type": null
}
```

## Configuration

### Ollama endpoint & model

| 환경변수 | 기본값 | 설명 |
|---------|--------|------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama 서버 주소 |
| `OLLAMA_MODEL` | `gpt-oss:20b` | 사용할 LLM 모델 |

```bash
export OLLAMA_BASE_URL=http://ollama-service:11434
export OLLAMA_MODEL=qwen3-coder:30b
```

**권장 모델 (성능 순):**

| 모델 | 크기 | 특징 |
|------|------|------|
| `qwen3-coder:30b` | ~18GB | 코드 이해·JSON 출력 최고 수준, **권장** |
| `qwen2.5-coder:14b` | ~8.7GB | 메모리 여유가 적을 때, JSON 안정적 |
| `gpt-oss:20b` | ~13GB | 기본값, tactic_classifier에서 간헐적 빈 응답 발생 |

> **Qwen3 계열 주의사항**: thinking 모드가 기본으로 활성화되어 있으나, 이 에이전트는 시스템 프롬프트에 `/no_think` 토큰을 포함해 자동으로 비활성화합니다.

### Colima 환경 (macOS)

Docker Desktop과 달리 Colima은 `host.docker.internal`을 자동으로 지원하지 않습니다.
컨테이너에서 호스트의 Ollama에 접근하려면 아래 두 가지 설정이 필요합니다.

**1. Ollama를 모든 인터페이스에 바인딩**

Ollama 기본값은 `127.0.0.1`만 수신합니다. Colima VM에서 접근하려면 `0.0.0.0`으로 재시작해야 합니다.

```bash
# Ollama.app 종료 후 터미널에서 실행
pkill ollama
OLLAMA_HOST=0.0.0.0 ollama serve &

# 바인딩 확인 — *.11434 항목이 보여야 함
netstat -an | grep 11434
```

**2. Colima 게이트웨이 IP 확인**

```bash
# Colima VM 내부에서 호스트 IP 확인
colima ssh -- ip route | grep default
# 예: default via 192.168.5.2 dev eth0 ...
#                 ^^^^^^^^^^^^^ 이 IP를 OLLAMA_BASE_URL에 사용
```

**3. docker run 명령에 적용**

```bash
docker run --rm \
  -v /path/to/project:/workspace \
  -v $(pwd)/out:/out \
  -v chroma-model-cache:/root/.cache/chroma \
  -e OLLAMA_BASE_URL=http://192.168.5.2:11434 \
  -e OLLAMA_MODEL=qwen3-coder:30b \
  --entrypoint analyze \
  analysis-agent /workspace --id my-project --output /out/my-project.json
```

> `-v chroma-model-cache:/root/.cache/chroma` 는 임베딩 모델(~80MB)을 Docker 볼륨에 캐시해 재실행 시 다운로드를 건너뜁니다.

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
4. 새 출력이 최종 결과에 포함돼야 한다면 `schema.py`의 `ModuleProperty`와 `aggregator.py`도 수정
5. Register the node and edges in `graph.py`:

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

`tactic_classifier`는 두 단계로 MITRE ATT&CK ID와 기능 분류를 결정합니다.

1. **LLM** (RAG 컨텍스트 기반): `module_category`, `capabilities`, `post_exploits`, `custom_tags`, MITRE ID 반환
2. **결정론적 후처리 (`_enrich_mitre`, `_derive_*`)**: LLM 결과에 누락된 항목 보완
   - `_TAG_MITRE`: custom_tags → tactics/techniques 룩업 테이블
   - `_SIGNAL_MITRE`: RAG 컨텍스트 코드 패턴 매칭
   - `_TAG_TO_CATEGORY`, `_TAG_TO_CAPABILITIES`, `_TAG_TO_POST_EXPLOITS`: 기능 분류 보완
   - LLM 실패 시에도 컨텍스트 기반 결정론적 분류 제공

매핑 규칙 추가/수정: `src/analysis_agent/nodes/tactic_classifier.py`의 `_TAG_MITRE`, `_SIGNAL_MITRE`, `_TAG_TO_CATEGORY`, `_TAG_TO_CAPABILITIES`, `_TAG_TO_POST_EXPLOITS`.

## Tech Stack

- **LLM**: Ollama (`gpt-oss:20b`)
- **Framework**: LangChain + LangGraph (StateGraph)
- **Indexing**: tree-sitter 0.25 + ChromaDB
- **Interface**: Typer CLI + FastAPI REST
- **Output**: JSON (MongoDB schema compatible)
