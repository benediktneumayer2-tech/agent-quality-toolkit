import math

import pytest

from aqt_validate.stats import (auroc, betainc, clopper_pearson, fleiss_kappa, min_n_zero_failures, percentile,
                                rate)

# Reference values computed once with scipy.stats.beta.ppf (not a dependency).
REFERENCE_TWO_SIDED = {
    (5, 10): (0.18708602844739855, 0.8129139715526015),
    (59, 80): (0.6271491697875681, 0.8295907488995917),
    (3, 1000): (0.0006190999316495713, 0.008742023238478303),
    (500, 100000): (0.0045722441500705875, 0.005456841177010281),
    (4, 102): (0.010786651332693993, 0.09737096247713449),
}
REFERENCE_ONE_SIDED = {
    (5, 10): (0.2224411010081294, 0.7775588989918706),
    (59, 80): (0.6444349362238084, 0.8168689242389124),
    (4, 102): (0.013504267318042499, 0.0874919003081029),
}


@pytest.mark.parametrize("kn,expected", REFERENCE_TWO_SIDED.items())
def test_clopper_pearson_two_sided(kn, expected):
    lo, hi = clopper_pearson(*kn)
    assert lo == pytest.approx(expected[0], abs=1e-9)
    assert hi == pytest.approx(expected[1], abs=1e-9)


@pytest.mark.parametrize("kn,expected", REFERENCE_ONE_SIDED.items())
def test_clopper_pearson_one_sided(kn, expected):
    lo, hi = clopper_pearson(*kn, sided="one")
    assert (lo, hi) == pytest.approx(expected, abs=1e-9)


def test_zero_and_full_counts():
    assert clopper_pearson(0, 102, sided="one")[1] == pytest.approx(1 - 0.05 ** (1 / 102), abs=1e-12)
    assert clopper_pearson(0, 176, sided="one")[1] == pytest.approx(0.016877, abs=1e-6)
    assert clopper_pearson(0, 10)[0] == 0.0
    assert clopper_pearson(10, 10)[1] == 1.0
    assert clopper_pearson(1, 1)[0] == pytest.approx(0.025, abs=1e-12)
    assert clopper_pearson(0, 0) == (0.0, 1.0)
    with pytest.raises(ValueError):
        clopper_pearson(5, 3)


def test_betainc_known_values():
    assert betainc(1, 1, 0.3) == pytest.approx(0.3)
    assert betainc(2, 3, 0.4) == pytest.approx(0.5248)  # 1 - P(Bin(4,0.4) <= 1)
    assert betainc(0.5, 0.5, 0.5) == pytest.approx(0.5)


def test_rate_integers_are_conservative():
    r = rate(4, 102)
    assert all(isinstance(v, int) for v in r.values())
    assert r["lo_ppm"] <= 10786.65 and r["hi_ppm"] >= 97370.96
    assert r["lower1_ppm"] == 13504 and r["upper1_ppm"] == 87492
    assert rate(0, 0) == {"k": 0, "n": 0}


def test_min_n_zero_failures():
    assert min_n_zero_failures(0.01) == 299
    assert min_n_zero_failures(0.05) == 59
    n = min_n_zero_failures(0.01)
    assert clopper_pearson(0, n, sided="one")[1] <= 0.01 < clopper_pearson(0, n - 1, sided="one")[1]


def test_auroc_with_ties():
    assert auroc([0.1, 0.4, 0.35, 0.8], [0.8, 0.9]) == pytest.approx(0.9375)
    assert auroc([1, 2], [3, 4]) == 1.0
    assert auroc([3, 4], [1, 2]) == 0.0
    assert auroc([1, 1], [1, 1]) == 0.5
    assert auroc([], [1]) is None


def test_fleiss_kappa_reference():
    # Fleiss (1971) style example as used on Wikipedia: 10 subjects, 14 raters, 5 categories -> 0.210
    table = [[0, 0, 0, 0, 14], [0, 2, 6, 4, 2], [0, 0, 3, 5, 6], [0, 3, 9, 2, 0], [2, 2, 8, 1, 1],
             [7, 7, 0, 0, 0], [3, 2, 6, 3, 0], [2, 5, 3, 2, 2], [6, 5, 2, 1, 0], [0, 2, 2, 3, 7]]
    assert fleiss_kappa(table) == pytest.approx(0.20993, abs=1e-5)
    assert fleiss_kappa([[3, 0], [0, 3]]) == pytest.approx(1.0)
    assert fleiss_kappa([[3, 0], [3, 0]]) is None  # one category only: undefined
    assert fleiss_kappa([[1, 0]]) is None  # one rater
    with pytest.raises(ValueError):
        fleiss_kappa([[2, 1], [1, 1]])


def test_percentile_nearest_rank():
    values = list(range(1, 101))
    assert percentile(values, 50) == 50
    assert percentile(values, 95) == 95
    assert percentile([7], 95) == 7
    assert percentile([], 50) is None
    assert math.isclose(percentile([1.5, 2.5], 100), 2.5)
