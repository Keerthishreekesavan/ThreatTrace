"""Upload + dataset listing endpoints."""

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.pipeline import (
    SourceFileMissingError,
    reanalyze_dataset,
    run_pipeline_and_persist,
)
from api.schemas import (
    ColumnMappingOut,
    DatasetDetailOut,
    DatasetOut,
    OntologyFieldOut,
    SchemaOverrideIn,
)
from db.models import Dataset
from db.session import get_db
from ingestion.loader import UnsupportedFileTypeError
from ingestion.ontology import ONTOLOGY
from ingestion.schema_mapper import UnknownOntologyFieldError

router = APIRouter(prefix="/api/datasets", tags=["datasets"])
ontology_router = APIRouter(prefix="/api/ontology", tags=["ontology"])

ALLOWED_SUFFIXES = {".csv", ".json"}


@ontology_router.get("", response_model=list[OntologyFieldOut])
def list_ontology_fields():
    """The canonical fields a column can be mapped to - drives the override
    dropdown so the UI never hardcodes a copy of the ontology."""
    return [
        OntologyFieldOut(
            key=c.key,
            display_name=c.display_name,
            description=c.description,
            expected_dtype=c.expected_dtype,
        )
        for c in ONTOLOGY
    ]


@router.post("", response_model=DatasetDetailOut)
def upload_dataset(file: UploadFile = File(...), db: Session = Depends(get_db)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Upload a .csv or .json log file.",
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = Path(tmp.name)

    try:
        dataset = run_pipeline_and_persist(db, file.filename or tmp_path.name, tmp_path)
    except UnsupportedFileTypeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse log file: {exc}") from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    return dataset


@router.get("", response_model=list[DatasetOut])
def list_datasets(db: Session = Depends(get_db)):
    return db.scalars(select(Dataset).order_by(Dataset.uploaded_at.desc())).all()


@router.get("/{dataset_id}", response_model=DatasetDetailOut)
def get_dataset(dataset_id: int, db: Session = Depends(get_db)):
    dataset = db.get(Dataset, dataset_id)
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return dataset


@router.get("/{dataset_id}/schema", response_model=list[ColumnMappingOut])
def get_dataset_schema(dataset_id: int, db: Session = Depends(get_db)):
    """Exposes exactly how each original column was semantically interpreted -
    the transparency view behind the adaptive ingestion claim."""
    dataset = db.get(Dataset, dataset_id)
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return _schema_out(dataset)


def _schema_out(dataset: Dataset) -> list[ColumnMappingOut]:
    return [
        ColumnMappingOut(
            column_name=column,
            mapped_field=info.get("mapped_field"),
            confidence=info.get("confidence", 0.0),
            source=info.get("source", "inferred"),
            inferred_dtype=info.get("inferred_dtype"),
            sample_values=info.get("sample_values", []),
        )
        for column, info in (dataset.mapping_summary or {}).items()
    ]


@router.put("/{dataset_id}/schema", response_model=list[ColumnMappingOut])
def override_dataset_schema(
    dataset_id: int,
    body: SchemaOverrideIn,
    db: Session = Depends(get_db),
):
    """Applies analyst corrections to the inferred column mapping and re-runs
    the whole analysis against the retained source file.

    This is the escape hatch for the mapper's real weakness: a low-confidence
    match produces a *wrong* finding rather than no finding, and only a human
    can tell that (say) a `request_count` column isn't a failed-login count.
    """
    dataset = db.get(Dataset, dataset_id)
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    known = set(dataset.mapping_summary or {})
    unknown_columns = set(body.overrides) - known
    if unknown_columns:
        raise HTTPException(
            status_code=422,
            detail=f"Not a column in this dataset: {', '.join(sorted(unknown_columns))}",
        )

    duplicates = [
        field
        for field in {v for v in body.overrides.values() if v}
        if list(body.overrides.values()).count(field) > 1
    ]
    if duplicates:
        raise HTTPException(
            status_code=422,
            detail=f"Each canonical field can be assigned once; repeated: {', '.join(sorted(duplicates))}",
        )

    try:
        reanalyze_dataset(db, dataset, dict(body.overrides))
    except UnknownOntologyFieldError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SourceFileMissingError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return _schema_out(dataset)
