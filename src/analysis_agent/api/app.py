"""FastAPI application — async REST interface."""
import asyncio
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Project Analysis Agent", version="0.1.0")


class AnalyzePathRequest(BaseModel):
    repo_path: str
    project_id: Optional[str] = None
    custom_vocabulary_path: Optional[str] = None


class AnalysisResponse(BaseModel):
    project_id: str
    status: str          # "completed" | "accepted"
    result: Optional[dict] = None


# In-memory job store (replace with Redis/DB for production)
_jobs: dict[str, dict] = {}


def _run_and_store(job_id: str, repo_path: str, project_id: str, custom_vocab: str | None, cleanup_dir: str | None):
    from analysis_agent.runner import run_analysis
    try:
        result, _reasoning = run_analysis(repo_path=repo_path, project_id=project_id, custom_vocabulary_path=custom_vocab)
        _jobs[job_id] = {"status": "completed", "result": result}
    except Exception as e:
        _jobs[job_id] = {"status": "failed", "error": str(e)}
    finally:
        if cleanup_dir and os.path.isdir(cleanup_dir):
            shutil.rmtree(cleanup_dir, ignore_errors=True)


@app.post("/analyze/path", response_model=AnalysisResponse)
async def analyze_path(req: AnalyzePathRequest):
    """Synchronous analysis of a path already accessible on the filesystem."""
    from analysis_agent.runner import run_analysis

    project_id = req.project_id or Path(req.repo_path).name
    try:
        result, _reasoning = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: run_analysis(
                repo_path=req.repo_path,
                project_id=project_id,
                custom_vocabulary_path=req.custom_vocabulary_path,
            ),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return AnalysisResponse(project_id=project_id, status="completed", result=result)


@app.post("/analyze/upload")
async def analyze_upload(
    file: UploadFile,
    background_tasks: BackgroundTasks,
    project_id: Optional[str] = None,
):
    """Accept a zip archive, extract it, and run analysis asynchronously."""
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted")

    job_id = str(uuid.uuid4())
    pid = project_id or Path(file.filename).stem
    tmp_dir = tempfile.mkdtemp(prefix=f"analysis_{job_id}_")

    zip_path = os.path.join(tmp_dir, file.filename)
    with open(zip_path, "wb") as f:
        content = await file.read()
        f.write(content)

    import zipfile
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(tmp_dir)
    os.remove(zip_path)

    # Find the extracted root (may have a single top-level dir)
    entries = [e for e in os.listdir(tmp_dir) if not e.startswith(".")]
    repo_path = tmp_dir
    if len(entries) == 1 and os.path.isdir(os.path.join(tmp_dir, entries[0])):
        repo_path = os.path.join(tmp_dir, entries[0])

    _jobs[job_id] = {"status": "accepted"}

    background_tasks.add_task(
        _run_and_store,
        job_id=job_id,
        repo_path=repo_path,
        project_id=pid,
        custom_vocab=None,
        cleanup_dir=tmp_dir,
    )

    return JSONResponse({"job_id": job_id, "project_id": pid, "status": "accepted"})


@app.get("/analyze/{job_id}")
async def get_result(job_id: str):
    """Poll for async job result."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JSONResponse({"job_id": job_id, **job})


@app.get("/health")
async def health():
    return {"status": "ok"}
