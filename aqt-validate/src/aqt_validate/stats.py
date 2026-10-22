"""Statistics used by validation reports (standard library only).

- exact Clopper-Pearson bounds for a binomial proportion;
- AUROC as the Mann-Whitney U statistic (ties count one half);
- Fleiss' kappa for several raters;
- nearest-rank percentiles and the smallest sample that can show a false-positive rate.

Rates in evidence records are integers in parts per million (ppm). Lower bounds are
rounded down and upper bounds up, so the integer form is never less conservative.
"""

from __future__ import annotations

import math
from typing import Iterable, Sequence

PPM = 1_000_000


# --------------------------------------------------------------------------- beta / binomial

def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (modified Lentz)."""
    tiny, eps = 1e-300, 3e-16
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 100_000):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function I_x(a, b) for a, b > 0."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_front = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                 + a * math.log(x) + b * math.log1p(-x))
    front = math.exp(log_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def _solve_increasing(f, target: float) -> float:
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if f(mid) < target:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-15:
            break
    return (lo + hi) / 2.0


def clopper_pearson(k: int, n: int, conf: float = 0.95, sided: str = "two") -> tuple[float, float]:
    """Exact (Clopper-Pearson) bounds for k successes in n trials.

    ``sided="two"`` gives the central interval at confidence ``conf``; ``"one"`` gives
    one-sided bounds (each bound alone holds with confidence ``conf``).
    """
    if not (isinstance(k, int) and isinstance(n, int)) or n < 0 or not 0 <= k <= n:
        raise ValueError(f"need integers 0 <= k <= n, got k={k}, n={n}")
    if n == 0:
        return 0.0, 1.0
    if not 0.0 < conf < 1.0:
        raise ValueError("conf must be between 0 and 1")
    tail = (1.0 - conf) / (2.0 if sided == "two" else 1.0)
    # P(X >= k | p) = I_p(k, n-k+1) increases with p; P(X <= k | p) = 1 - I_p(k+1, n-k).
    lower = 0.0 if k == 0 else _solve_increasing(lambda p: betainc(k, n - k + 1, p), tail)
    upper = 1.0 if k == n else _solve_increasing(lambda p: betainc(k + 1, n - k, p), 1.0 - tail)
    return lower, upper


def floor_ppm(x: float) -> int:
    return max(0, min(PPM, math.floor(x * PPM + 1e-7)))


def ceil_ppm(x: float) -> int:
    return max(0, min(PPM, math.ceil(x * PPM - 1e-7)))


def rate(k: int, n: int, conf: float = 0.95) -> dict:
    """A proportion with its bounds, as integers (ppm) for evidence records.

    ``lo_ppm``/``hi_ppm``: two-sided interval; ``lower1_ppm``/``upper1_ppm``: one-sided bounds.
    """
    if n == 0:
        return {"k": 0, "n": 0}
    lo, hi = clopper_pearson(k, n, conf, "two")
    lo1, hi1 = clopper_pearson(k, n, conf, "one")
    return {"k": k, "n": n, "rate_ppm": round(k * PPM / n), "lo_ppm": floor_ppm(lo), "hi_ppm": ceil_ppm(hi),
            "lower1_ppm": floor_ppm(lo1), "upper1_ppm": ceil_ppm(hi1)}


def min_n_zero_failures(rate_limit: float, conf: float = 0.95) -> int:
    """Smallest n for which 0 failures in n gives a one-sided upper bound <= rate_limit."""
    if not 0.0 < rate_limit < 1.0:
        raise ValueError("rate_limit must be between 0 and 1")
    return math.ceil(math.log(1.0 - conf) / math.log(1.0 - rate_limit) - 1e-9)


# --------------------------------------------------------------------------- separation and agreement

def auroc(negatives: Sequence[float], positives: Sequence[float]) -> float | None:
    """Area under the ROC curve = P(score_pos > score_neg) + 0.5 P(tie)."""
    if not negatives or not positives:
        return None
    merged = sorted([(v, 0) for v in negatives] + [(v, 1) for v in positives])
    rank_sum, i = 0.0, 0
    while i < len(merged):
        j = i
        while j < len(merged) and merged[j][0] == merged[i][0]:
            j += 1
        average_rank = (i + 1 + j) / 2.0
        rank_sum += average_rank * sum(1 for _, label in merged[i:j] if label == 1)
        i = j
    n_pos, n_neg = len(positives), len(negatives)
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def fleiss_kappa(table: Sequence[Sequence[int]]) -> float | None:
    """Fleiss' kappa. ``table[i][j]`` = raters putting subject i in category j (same raters per row).

    Returns None when undefined (fewer than 2 raters, no subjects, or every rating in one category).
    """
    rows = [list(map(int, row)) for row in table]
    if not rows:
        return None
    raters = sum(rows[0])
    if any(sum(row) != raters for row in rows):
        raise ValueError("every subject needs the same number of ratings")
    if raters < 2:
        return None
    subjects = len(rows)
    categories = len(rows[0])
    p_j = [sum(row[j] for row in rows) / (subjects * raters) for j in range(categories)]
    p_i = [(sum(c * c for c in row) - raters) / (raters * (raters - 1)) for row in rows]
    p_bar = sum(p_i) / subjects
    p_e = sum(p * p for p in p_j)
    if p_e >= 1.0 - 1e-12:
        return None
    return (p_bar - p_e) / (1.0 - p_e)


def percentile(values: Iterable[float], q: float) -> float | None:
    """Nearest-rank percentile (q in 0..100)."""
    data = sorted(values)
    if not data:
        return None
    index = max(0, math.ceil(q / 100.0 * len(data)) - 1)
    return data[min(index, len(data) - 1)]
