FROM python:3.11-slim

WORKDIR /app

# Step 1: install dependencies (layer cached unless pyproject.toml changes)
# A stub src/analysis_agent/__init__.py satisfies setuptools' editable-install
# requirement without copying the full source yet.
COPY pyproject.toml .
RUN mkdir -p src/analysis_agent && \
    touch src/analysis_agent/__init__.py && \
    pip install --no-cache-dir -e .

# Step 2: overwrite stub with real source (only this layer re-runs on code changes)
COPY src/ ./src/
COPY config/ ./config/

ENV OLLAMA_BASE_URL=http://ollama-service:11434

EXPOSE 8080

ENTRYPOINT ["python", "-m", "analysis_agent.api.routes"]
