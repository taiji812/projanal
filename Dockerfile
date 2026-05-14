FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[all]" 2>/dev/null || pip install --no-cache-dir -e .

COPY config/ ./config/
COPY src/ ./src/

ENV OLLAMA_BASE_URL=http://ollama-service:11434

EXPOSE 8080

ENTRYPOINT ["python", "-m", "analysis_agent.api.routes"]
