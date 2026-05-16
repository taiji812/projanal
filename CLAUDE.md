# ProjectAnalysisAgent

소스코드 프로젝트를 분석해 기능·빌드·산출물·MITRE ATT&CK 전술/기법 정보를 JSON으로 추출하는 멀티 에이전트 시스템.

## 기술 스택

- **LLM**: Ollama (`gpt-oss:20b`) — 로컬 개발 시 `http://localhost:11434`, 운영 시 `http://ollama-service:11434`
- **프레임워크**: LangChain + LangGraph (StateGraph)
- **인터페이스**: Typer CLI + FastAPI REST
- **출력**: JSON (MongoDB 스키마와 호환)
- **Python**: 3.11+

## 프로젝트 구조

```
src/analysis_agent/
├── state.py           # LangGraph TypedDict 상태 정의 (AnalysisState)
├── graph.py           # StateGraph 구성 — fan-out/fan-in 패턴
├── runner.py          # AgentRunner: CLI·REST 공통 진입점
├── cli.py             # Typer CLI (analyze 커맨드)
├── nodes/
│   ├── file_explorer.py      # 파일트리 탐색, 핵심 파일 식별 (LLM 없음)
│   ├── language_analyzer.py  # 언어 구성 비율 계산 (LLM 없음)
│   ├── build_analyzer.py     # 빌드 도구·커맨드·파라미터 추출 (LLM)
│   ├── artifact_analyzer.py  # 빌드 산출물 추출 (LLM)
│   ├── tactic_classifier.py  # MITRE ATT&CK 전술/기법 분류 (LLM)
│   └── aggregator.py         # 병렬 노드 결과 병합 → 최종 JSON
├── tools/
│   └── filesystem.py  # read_file, list_directory, grep_content, find_files_*
├── vocabulary/
│   └── loader.py      # YAML vocabulary 로드 + LLM 프롬프트용 포맷 변환
└── api/
    └── app.py         # FastAPI: POST /analyze/path, POST /analyze/upload, GET /analyze/{job_id}

config/vocabulary/
├── mitre_attack_enterprise.yaml  # MITRE ATT&CK Enterprise v15 전술/기법
└── custom.yaml                   # 커스텀 태그 (C2 Framework, Implant 등)
```

## 그래프 실행 흐름

```
START → file_explorer → [language_analyzer, build_analyzer, artifact_analyzer, tactic_classifier] → aggregator → END
```

- `file_explorer`는 순차 실행 (이후 노드들이 `key_files`, `file_tree`에 의존)
- 4개 분석 노드는 LangGraph fan-out으로 병렬 실행
- `aggregator`는 모든 병렬 노드 완료 후 fan-in

## 로컬 실행

```bash
# 패키지 설치
pip install -e .

# CLI 분석
analyze /path/to/project --id my-project --output result.json

# REST 서버 시작
python -m analysis_agent.api.routes

# Python에서 직접 호출
from analysis_agent.runner import run_analysis
result = run_analysis("/path/to/project", project_id="my-project")
```

## 출력 JSON 스키마

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
      { "name": "Configuration", "type": "choice", "default": "Release",
        "choices": ["Debug", "Release"], "description": "...", "source": "Lilith.sln" }
    ],
    "notes": "..."
  },
  "artifacts": [
    { "filename": "Lilith.exe", "output_path": "Release\\x64",
      "artifact_type": "exe", "description": "..." }
  ],
  "errors": []
}
```

## 새 노드 추가 방법

1. `src/analysis_agent/nodes/` 아래 새 파일 생성
2. 함수 시그니처: `def my_node(state: AnalysisState) -> dict`
3. 반환 딕셔너리에 항상 `"completed_nodes": ["my_node"]`, `"errors": []` 포함
4. `state.py`의 `AnalysisState`에 출력 필드 추가
5. `graph.py`에서 노드 등록 및 엣지 연결

```python
# graph.py 예시
g.add_node("my_node", my_node)
g.add_edge("file_explorer", "my_node")   # 병렬 추가
g.add_edge("my_node", "aggregator")
```

## Vocabulary 확장

`config/vocabulary/custom.yaml`에 항목 추가:

```yaml
custom_tags:
  - name: "My Custom Tag"
    description: "설명"
```

MITRE ATT&CK 항목 추가는 `mitre_attack_enterprise.yaml`의 `tactics` / `techniques` 배열에 동일한 형식으로 추가.

## LLM 프롬프트 설계 주의사항

- `format_vocabulary_context()`는 vocabulary를 `ID(Name)` 형식으로 압축 (~300 토큰)
  - 설명문을 포함하면 ~3,000 토큰이 되어 gpt-oss:20b에서 JSON 응답 실패 발생
  - 70B+ 모델로 교체 시 long-form 포맷이 더 나을 수 있음
- LLM 노드는 모두 `format="json"`으로 호출해 JSON 응답을 강제
- Pydantic 모델로 LLM 응답을 검증 후 state에 저장

## tactic_classifier 2단계 MITRE 분류

MITRE ATT&CK ID 매핑은 LLM이 과도하게 보수적으로 처리하는 경향이 있음.
프롬프트에 매핑 힌트를 추가하면 컨텍스트가 길어져 오히려 빈 응답 발생 (gpt-oss:20b 실험 결과).

현재 구조:
1. **LLM 호출** (짧은 프롬프트): `custom_tags` + LLM이 인식한 MITRE ID 반환
2. **`_enrich_mitre()` 후처리** (결정론적): LLM 결과에 누락된 ID를 추가
   - `custom_tags → MITRE` 룩업 테이블 (`_TAG_MITRE`)
   - RAG 컨텍스트 코드 시그널 패턴 매칭 (`_SIGNAL_MITRE`)
   - LLM 실패 시에도 컨텍스트 기반 결정론적 분류 제공

MITRE 매핑 룰 추가/수정: `tactic_classifier.py`의 `_TAG_MITRE`, `_SIGNAL_MITRE` 딕셔너리 편집.

## 배포 (사이드카 패턴)

기존 서비스 파드와 동일한 볼륨을 공유해 로컬 파일시스템으로 분석:

```yaml
volumes:
  - name: workspace
    emptyDir: {}    # 또는 Longhorn PVC
containers:
  - name: main-service
    volumeMounts:
      - name: workspace
        mountPath: /workspace
  - name: analysis-agent
    volumeMounts:
      - name: workspace
        mountPath: /workspace
    env:
      - name: OLLAMA_BASE_URL
        value: http://ollama-service:11434
```

기존 서비스 → CLI 호출: `analyze /workspace/{repo-id}/ --id {project-id}`
