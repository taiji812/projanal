"""Uvicorn entrypoint helper."""
import uvicorn

from analysis_agent.api.app import app


def serve(host: str = "0.0.0.0", port: int = 8080, reload: bool = False):
    uvicorn.run(app, host=host, port=port, reload=reload)


if __name__ == "__main__":
    serve()
