"""Semantic schema mapping: matches arbitrary input columns to the ontology.

Two embedding backends are supported behind the same interface:

- `SentenceTransformerEmbedder`: real sentence embeddings (semantic, handles
  synonyms/paraphrase well). Used when `sentence-transformers` + `torch` are
  installed.
- `TfidfEmbedder`: pure scikit-learn fallback (no torch dependency) built by
  vectorizing the ontology descriptions together with the incoming column
  descriptors. Weaker at true paraphrase understanding but still captures
  shared domain vocabulary ("fail", "auth", "login", "port", ...), and
  crucially has zero risk of failing to install.

Whichever backend is active, matching itself is identical: embed every
column descriptor and every ontology concept description, score by cosine
similarity, add small heuristic bonuses for name-hint substring matches and
dtype compatibility, then resolve column<->concept assignment with a greedy
bipartite match (highest-confidence pairs win first) so two columns don't
both latch onto the same concept.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd

from .ontology import ONTOLOGY, ONTOLOGY_BY_KEY, MIN_MAPPING_CONFIDENCE, OntologyConcept
from .semantic_analyzer import ColumnProfile, profile_dataframe

try:
    from sentence_transformers import SentenceTransformer

    _SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    _SENTENCE_TRANSFORMERS_AVAILABLE = False


class SentenceTransformerEmbedder:
    _model = None
    # Real sentence embeddings for matching/non-matching descriptions
    # typically sit ~0.2-0.4 apart in cosine similarity, so a moderate
    # temperature is enough to produce a confidently peaked softmax.
    softmax_temperature = 0.1

    @classmethod
    def _get_model(cls):
        if cls._model is None:
            cls._model = SentenceTransformer("all-MiniLM-L6-v2")
        return cls._model

    def embed(self, texts: list[str]) -> np.ndarray:
        model = self._get_model()
        vectors = model.encode(texts, normalize_embeddings=True)
        return np.asarray(vectors)


class TfidfEmbedder:
    # TF-IDF cosine similarities live on a much smaller absolute scale than
    # sentence embeddings (short descriptors share little vocabulary with
    # the ontology's prose descriptions), so a much smaller temperature is
    # needed for the softmax to meaningfully separate a real match from
    # noise. Calibrated against the bundled sample datasets.
    softmax_temperature = 0.05

    def embed(self, texts: list[str]) -> np.ndarray:
        from sklearn.feature_extraction.text import TfidfVectorizer

        vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        matrix = vectorizer.fit_transform(texts)
        norm = np.linalg.norm(matrix.toarray(), axis=1, keepdims=True)
        norm[norm == 0] = 1.0
        return matrix.toarray() / norm


def get_default_embedder():
    if _SENTENCE_TRANSFORMERS_AVAILABLE:
        return SentenceTransformerEmbedder()
    return TfidfEmbedder()


_DTYPE_COMPATIBILITY = {
    "ip": {"ip"},
    "integer": {"integer", "float"},
    "float": {"integer", "float"},
    "datetime": {"datetime"},
    "categorical": {"categorical", "string"},
    "string": {"categorical", "string"},
}


def _name_hint_bonus(column_name: str, concept: OntologyConcept) -> float:
    lowered = column_name.lower()
    return 0.08 if any(hint in lowered for hint in concept.name_hints) else 0.0


def _dtype_bonus(profile: ColumnProfile, concept: OntologyConcept) -> float:
    """Rewards a dtype-compatible concept and *penalizes* an incompatible one.

    The penalty matters as much as the bonus: a column name can share
    vocabulary with a concept it has nothing to do with (a string
    'cost_centre_code' vs the integer 'status_code' concept), and the
    observed value shape is the strongest available signal for rejecting
    that. An unrecognized/empty dtype stays neutral rather than penalized,
    since we genuinely don't know.
    """
    if profile.inferred_dtype not in _DTYPE_COMPATIBILITY:
        return 0.0
    compatible = _DTYPE_COMPATIBILITY[profile.inferred_dtype]
    return 0.05 if concept.expected_dtype in compatible else -0.10


@dataclass
class ColumnMapping:
    column_name: str
    mapped_field: str | None
    confidence: float
    profile: ColumnProfile
    # "inferred" when the mapper chose it, "manual" when an analyst did. Manual
    # mappings are authoritative and reported at full confidence.
    source: str = "inferred"


class UnknownOntologyFieldError(ValueError):
    pass


def map_columns(
    df: pd.DataFrame,
    embedder=None,
    overrides: dict[str, str | None] | None = None,
) -> list[ColumnMapping]:
    """Maps each input column to a canonical field.

    `overrides` lets an analyst correct the inference: `{"status":
    "failed_attempts"}` pins that column, and `{"request_count": None}` forces a
    column to stay unmapped. A pinned concept is withdrawn from the automatic
    contest, so whichever column previously held it is re-matched against what's
    left rather than silently duplicating the field.
    """
    overrides = {k: v for k, v in (overrides or {}).items() if k in df.columns}

    unknown = {
        v for v in overrides.values() if v is not None and v not in ONTOLOGY_BY_KEY
    }
    if unknown:
        raise UnknownOntologyFieldError(
            f"Unknown canonical field(s): {', '.join(sorted(unknown))}"
        )

    embedder = embedder or get_default_embedder()
    profiles = profile_dataframe(df)
    columns = list(profiles.keys())

    if not columns:
        return []

    concept_texts = [c.description for c in ONTOLOGY]
    column_texts = [profiles[col].descriptor for col in columns]

    all_embeddings = embedder.embed(concept_texts + column_texts)
    concept_embeddings = all_embeddings[: len(ONTOLOGY)]
    column_embeddings = all_embeddings[len(ONTOLOGY) :]

    # cosine similarity (embeddings from both backends are pre-normalized)
    similarity = column_embeddings @ concept_embeddings.T

    raw_scores = np.zeros((len(columns), len(ONTOLOGY)))
    for ci, col in enumerate(columns):
        profile = profiles[col]
        for oi, concept in enumerate(ONTOLOGY):
            score = float(similarity[ci, oi])
            score += _name_hint_bonus(col, concept)
            score += _dtype_bonus(profile, concept)
            raw_scores[ci, oi] = score

    # Per-column softmax turns "how does this concept's raw score compare to
    # the alternatives for this column" into a calibrated 0-1 confidence,
    # independent of the absolute score scale a given embedding backend
    # happens to produce (TF-IDF and sentence embeddings differ wildly here).
    temperature = getattr(embedder, "softmax_temperature", 0.1)
    scaled = raw_scores / temperature
    scaled -= scaled.max(axis=1, keepdims=True)  # numerical stability
    exp_scores = np.exp(scaled)
    confidence = exp_scores / exp_scores.sum(axis=1, keepdims=True)

    candidates: list[tuple[float, int, int]] = []  # (confidence, column_idx, concept_idx)
    for ci in range(len(columns)):
        for oi in range(len(ONTOLOGY)):
            candidates.append((float(confidence[ci, oi]), ci, oi))

    candidates.sort(key=lambda x: x[0], reverse=True)

    assigned_columns: set[int] = set()
    assigned_concepts: set[int] = set()
    best_for_column: dict[int, tuple[str, float]] = {}

    # Seed the assignment with the analyst's corrections, so both the column and
    # the concept are already claimed before automatic matching runs.
    concept_index = {c.key: i for i, c in enumerate(ONTOLOGY)}
    manual_columns: set[int] = set()
    for column_name, field in overrides.items():
        ci = columns.index(column_name)
        assigned_columns.add(ci)
        manual_columns.add(ci)
        if field is None:
            continue  # pinned as deliberately unmapped
        assigned_concepts.add(concept_index[field])
        best_for_column[ci] = (field, 1.0)

    for score, ci, oi in candidates:
        if ci in assigned_columns or oi in assigned_concepts:
            continue
        if score < MIN_MAPPING_CONFIDENCE:
            continue
        assigned_columns.add(ci)
        assigned_concepts.add(oi)
        best_for_column[ci] = (ONTOLOGY[oi].key, score)

    _prefer_source_ip_when_only_one_ip(columns, profiles, best_for_column, manual_columns)

    mappings: list[ColumnMapping] = []
    for ci, col in enumerate(columns):
        field, confidence = best_for_column.get(ci, (None, 0.0))
        mappings.append(
            ColumnMapping(
                column_name=col,
                mapped_field=field,
                confidence=round(confidence, 4),
                profile=profiles[col],
                source="manual" if ci in manual_columns else "inferred",
            )
        )
    return mappings


def _prefer_source_ip_when_only_one_ip(
    columns: list[str],
    profiles: dict[str, ColumnProfile],
    best_for_column: dict[int, tuple[str, float]],
    manual_columns: set[int] | None = None,
) -> None:
    """If a dataset has exactly one IP column, treat it as the source IP.

    A log with a single IP column (Windows Security's `IpAddress`, sshd's
    `rhost`, most WAF exports) is recording *who did this*, not what was
    contacted. Left to raw similarity that column can land on
    `destination_ip` - which is much worse than a coin flip, because every
    detector and the anomaly model group by `source_ip`, so the whole
    analysis silently finds nothing. Mutates `best_for_column` in place.
    """
    manual_columns = manual_columns or set()
    ip_indices = [
        ci for ci, col in enumerate(columns) if profiles[col].inferred_dtype == "ip"
    ]
    if len(ip_indices) != 1:
        return

    ci = ip_indices[0]
    if ci in manual_columns:
        return  # an explicit analyst decision outranks this heuristic
    assigned = {field for field, _ in best_for_column.values()}
    if "source_ip" in assigned:
        return

    field, confidence = best_for_column.get(ci, (None, 0.0))
    if field in ("destination_ip", None):
        # Keep the original confidence when we're re-pointing an existing
        # IP match; use a deliberately modest value if it was unmapped.
        best_for_column[ci] = ("source_ip", confidence or 0.5)
