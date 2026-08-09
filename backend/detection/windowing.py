"""Sliding-window helper shared by every rule-based detector.

Rather than bucket events into fixed calendar windows (which can split a
single burst across two buckets), this finds the *densest* window of a
given size for a sorted series of timestamps using a two-pointer scan -
i.e. "what's the most events from this group that ever occurred within any
W-minute span", which is what "short time interval" actually means for
brute force / spraying / scanning detection.
"""

from datetime import timedelta

import pandas as pd


def densest_window(timestamps: pd.Series, window: timedelta) -> tuple[int, pd.Timestamp | None, pd.Timestamp | None]:
    ts = timestamps.dropna().sort_values().reset_index(drop=True)
    if ts.empty:
        return 0, None, None

    best_count = 1
    best_start, best_end = ts.iloc[0], ts.iloc[0]
    left = 0

    for right in range(len(ts)):
        while ts.iloc[right] - ts.iloc[left] > window:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_start, best_end = ts.iloc[left], ts.iloc[right]

    return best_count, best_start, best_end


def rows_in_window(df: pd.DataFrame, ts_column: str, start: pd.Timestamp, end: pd.Timestamp) -> pd.DataFrame:
    mask = (df[ts_column] >= start) & (df[ts_column] <= end)
    return df.loc[mask]
