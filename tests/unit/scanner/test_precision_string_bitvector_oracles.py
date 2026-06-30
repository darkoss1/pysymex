"""CPython oracles for corrected precision-matrix string and mask cases."""

from __future__ import annotations

import runpy
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

CASES_ROOT = Path(__file__).parents[2] / "regression" / "precision_matrix" / "cases"


def _load_function(case_name: str) -> Callable[[str], int]:
    namespace = runpy.run_path(str(CASES_ROOT / f"{case_name}.py"))
    return cast("Callable[[str], int]", namespace["f"])


@pytest.mark.parametrize(
    ("positive_case", "safe_case", "witness"),
    [
        ("p23_ord_license_div0", "n23_ord_license_safe", "ABCD"),
        ("p24_hash_lowbyte_div0", "n24_hash_lowbyte_safe", "AZ"),
    ],
)
def test_precision_string_and_mask_oracles_are_reachable(
    positive_case: str,
    safe_case: str,
    witness: str,
) -> None:
    positive = _load_function(positive_case)
    safe = _load_function(safe_case)

    with pytest.raises(ZeroDivisionError):
        positive(witness)
    assert safe(witness) == 1
