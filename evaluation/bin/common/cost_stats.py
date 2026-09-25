"""Descriptive statistics and the deterministic paired-block bootstrap (BP-20260922-v6).

Pure Python and standard library only, so results do not depend on a numerical package version.
Nothing here reads evidence or touches the network.
"""

from __future__ import annotations

import math
import random
from typing import Optional, Sequence

DEFAULT_BOOTSTRAP_REPLICATES = 10_000
DEFAULT_CONFIDENCE_LEVEL = 0.95


def percentile(values: Sequence[float], pct: float) -> Optional[float]:
    """Linear-interpolated percentile (the common "type 7" definition). None for an empty input."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * pct / 100.0
    lower = int(math.floor(rank))
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def mean(values: Sequence[float]) -> Optional[float]:
    return math.fsum(values) / len(values) if values else None


def sample_stdev(values: Sequence[float]) -> Optional[float]:
    """Sample standard deviation (n - 1 denominator). None below two observations."""
    if len(values) < 2:
        return None
    centre = math.fsum(values) / len(values)
    return math.sqrt(math.fsum((v - centre) ** 2 for v in values) / (len(values) - 1))


def describe(values: Sequence[float]) -> dict:
    """Median, mean, sample standard deviation, minimum, maximum, p95, and p99."""
    return {
        "n": len(values),
        "median": percentile(values, 50),
        "mean": mean(values),
        "stdev": sample_stdev(values),
        "min": min(values) if values else None,
        "max": max(values) if values else None,
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
    }


def paired_block_bootstrap(
    values_a: Sequence[float],
    values_b: Sequence[float],
    seed: int,
    replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    confidence: float = DEFAULT_CONFIDENCE_LEVEL,
) -> dict:
    """Compares model A with model B over paired blocks.

    `values_a[i]` and `values_b[i]` are the per-block summaries (for example the block median latency)
    of the two models in the same paired block. The resampling unit is the paired block: block indexes are
    drawn with replacement and each drawn block contributes both of its values.

    Effects (A relative to B):
      absolute = mean(a) - mean(b)
      relative = mean(a) / mean(b) - 1   (None when mean(b) is zero)

    The random generator is seeded here, so the same inputs always give the same interval.
    """
    if len(values_a) != len(values_b):
        raise ValueError("paired blocks must have equally many values on both sides")
    n = len(values_a)
    if n == 0:
        raise ValueError("at least one paired block is required")

    def effects(indexes: Sequence[int]) -> tuple[float, Optional[float]]:
        mean_a = math.fsum(values_a[i] for i in indexes) / len(indexes)
        mean_b = math.fsum(values_b[i] for i in indexes) / len(indexes)
        return mean_a - mean_b, (None if mean_b == 0 else mean_a / mean_b - 1.0)

    point_abs, point_rel = effects(range(n))
    rng = random.Random(seed)
    abs_draws: list[float] = []
    rel_draws: list[float] = []
    for _ in range(replicates):
        absolute, relative = effects([rng.randrange(n) for _ in range(n)])
        abs_draws.append(absolute)
        if relative is not None:
            rel_draws.append(relative)

    tail = (1.0 - confidence) / 2.0 * 100.0
    return {
        "paired_blocks": n,
        "replicates": replicates,
        "seed": seed,
        "confidence_level": confidence,
        "absolute_effect": point_abs,
        "absolute_ci_low": percentile(abs_draws, tail),
        "absolute_ci_high": percentile(abs_draws, 100.0 - tail),
        "relative_effect": point_rel,
        "relative_ci_low": percentile(rel_draws, tail) if rel_draws else None,
        "relative_ci_high": percentile(rel_draws, 100.0 - tail) if rel_draws else None,
    }
