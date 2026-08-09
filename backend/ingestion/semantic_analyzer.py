"""Profiles raw input columns into descriptor text used for semantic matching.

For each column in an uploaded dataset we don't just look at the header name
(which varies wildly between log sources) - we also inspect a sample of
actual values and infer a coarse dtype. The combination of name + inferred
type + value-shape summary is turned into a natural-language descriptor
string, which is what actually gets embedded and compared against the
ontology in schema_mapper.py. This is what lets "usr_fail_cnt" and
"login_fail" and "authentication_errors" all resolve to the same concept
even though the raw names share no tokens.
"""

import re
from dataclasses import dataclass

import pandas as pd

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_SAMPLE_SIZE = 25


@dataclass
class ColumnProfile:
    name: str
    inferred_dtype: str
    sample_values: list[str]
    descriptor: str


def _infer_dtype(series: pd.Series) -> str:
    non_null = series.dropna()
    if non_null.empty:
        return "unknown"

    # A JSON log can leave lists/dicts in a cell (e.g. a nested array that
    # json_normalize didn't flatten). Those are unhashable, so nunique()
    # below would raise; stringify them and treat the column as free text.
    if non_null.map(lambda v: isinstance(v, (list, dict, set))).any():
        return "string"

    sample = non_null.astype(str).head(200)

    if sample.str.match(_IP_RE).mean() > 0.8:
        return "ip"

    try:
        pd.to_numeric(non_null)
        # integers vs floats matters less than "numeric" for our purposes
        return "integer" if (non_null.astype(str).str.match(r"^-?\d+$")).mean() > 0.8 else "float"
    except (ValueError, TypeError):
        pass

    try:
        parsed = pd.to_datetime(non_null.head(50), errors="raise", format="mixed")
        if parsed.notna().mean() > 0.8:
            return "datetime"
    except (ValueError, TypeError):
        pass

    unique_ratio = non_null.nunique() / max(len(non_null), 1)
    if unique_ratio < 0.05 and non_null.nunique() <= 20:
        return "categorical"

    return "string"


def _value_shape_summary(series: pd.Series, dtype: str) -> str:
    non_null = series.dropna()
    if non_null.empty:
        return "column is entirely empty"

    if dtype in ("integer", "float"):
        numeric = pd.to_numeric(non_null, errors="coerce").dropna()
        if numeric.empty:
            return "numeric column with no parseable values"
        return (
            f"numeric values ranging from {numeric.min():g} to {numeric.max():g}, "
            f"mean {numeric.mean():.2f}"
        )

    if dtype == "categorical":
        top = non_null.astype(str).value_counts().head(5).index.tolist()
        return f"categorical values, most common: {', '.join(top)}"

    if dtype == "ip":
        return "values formatted as dotted-decimal IPv4 addresses"

    if dtype == "datetime":
        return "values formatted as timestamps or dates"

    sample_vals = non_null.astype(str).unique()[:5]
    return f"text values, examples: {', '.join(sample_vals)}"


def profile_column(name: str, series: pd.Series) -> ColumnProfile:
    dtype = _infer_dtype(series)
    shape_summary = _value_shape_summary(series, dtype)
    sample_values = series.dropna().astype(str).unique()[:5].tolist()

    readable_name = re.sub(r"[_\-.]+", " ", name).strip()
    descriptor = (
        f"Column named '{name}' (read as '{readable_name}'). "
        f"Inferred type: {dtype}. {shape_summary}."
    )

    return ColumnProfile(
        name=name,
        inferred_dtype=dtype,
        sample_values=sample_values,
        descriptor=descriptor,
    )


def profile_dataframe(df: pd.DataFrame) -> dict[str, ColumnProfile]:
    sample_df = df.head(_SAMPLE_SIZE * 40) if len(df) > _SAMPLE_SIZE * 40 else df
    return {col: profile_column(col, sample_df[col]) for col in df.columns}
