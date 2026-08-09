"""ThreatTrace API entrypoint.

Run locally:  uvicorn main:app --reload
Interactive docs at http://localhost:8000/docs
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import analysis, datasets
from db.session import init_db
from ingestion.schema_mapper import _SENTENCE_TRANSFORMERS_AVAILABLE


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="ThreatTrace",
    description=(
        "Adaptive cybersecurity threat detection & analytics. Upload any CSV/JSON "
        "security log; ThreatTrace semantically infers its schema, normalizes it, "
        "detects threats, scores risk, and explains the evidence."
    ),
    version="1.0.0",
)

_allowed_origins = os.environ.get(
    "CORS_ORIGINS", "http://localhost:5173,http://localhost:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _allowed_origins if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(datasets.router)
app.include_router(datasets.ontology_router)
app.include_router(analysis.router)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    return {
        "status": "ok",
        "semantic_backend": (
            "sentence-transformers" if _SENTENCE_TRANSFORMERS_AVAILABLE else "tfidf-fallback"
        ),
    }
