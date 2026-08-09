"""DB engine/session setup.

Defaults to a local SQLite file so `uvicorn main:app` works with zero setup
during development. `docker-compose.yml` overrides `DATABASE_URL` to point
at the bundled Postgres service for the full stack.
"""

import os
from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./threattrace.db")

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


# Columns added after the first release. `create_all` only creates missing
# *tables*, so an existing database needs these appended explicitly. This is a
# deliberately minimal stand-in for Alembic - enough for additive columns, which
# is all this project has needed. Anything beyond that should introduce real
# migrations rather than extending this list.
_ADDITIVE_COLUMNS: dict[str, dict[str, str]] = {
    "datasets": {
        "source_path": "VARCHAR(1024)",
        "overrides": "JSON",
    },
}


def _add_missing_columns() -> None:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table, columns in _ADDITIVE_COLUMNS.items():
            if table not in existing_tables:
                continue
            present = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl_type in columns.items():
                if name not in present:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl_type}"))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
