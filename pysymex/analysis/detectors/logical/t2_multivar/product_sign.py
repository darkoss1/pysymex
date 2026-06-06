# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Product sign contradiction logical contradiction rule.

Detects contradictions where sign assertions on the product of two variables (e.g. x * y < 0)
contradict the signs of the individual variables (e.g., both x > 0 and y > 0).
"""

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import (
    extract_bounds,
    extract_product_const_comparisons,
)


def _strictly_positive(bounds: dict[str, int | None]) -> bool:
    """Determine if variable bounds guarantee a strictly positive value (> 0).

    Args:
        bounds: Dictionary containing bounds properties.

    Returns:
        True if the bounds imply the value is strictly positive, otherwise False.
    """
    min_val = bounds.get("min")
    min_strict = bounds.get("min_strict")
    return (min_val is not None and int(min_val) > 0) or (
        min_strict is not None and int(min_strict) >= 0
    )


def _nonnegative(bounds: dict[str, int | None]) -> bool:
    """Determine if variable bounds guarantee a non-negative value (>= 0).

    Args:
        bounds: Dictionary containing bounds properties.

    Returns:
        True if the bounds imply the value is non-negative, otherwise False.
    """
    min_val = bounds.get("min")
    min_strict = bounds.get("min_strict")
    return (min_val is not None and int(min_val) >= 0) or (
        min_strict is not None and int(min_strict) >= -1
    )


def _strictly_negative(bounds: dict[str, int | None]) -> bool:
    """Determine if variable bounds guarantee a strictly negative value (< 0).

    Args:
        bounds: Dictionary containing bounds properties.

    Returns:
        True if the bounds imply the value is strictly negative, otherwise False.
    """
    max_val = bounds.get("max")
    max_strict = bounds.get("max_strict")
    return (max_val is not None and int(max_val) < 0) or (
        max_strict is not None and int(max_strict) <= 0
    )


def _nonpositive(bounds: dict[str, int | None]) -> bool:
    """Determine if variable bounds guarantee a non-positive value (<= 0).

    Args:
        bounds: Dictionary containing bounds properties.

    Returns:
        True if the bounds imply the value is non-positive, otherwise False.
    """
    max_val = bounds.get("max")
    max_strict = bounds.get("max_strict")
    return (max_val is not None and int(max_val) <= 0) or (
        max_strict is not None and int(max_strict) <= 1
    )


class ProductSignContradictionRule(LogicRule):
    """Rule that matches contradictions between a product sign comparison and individual variable bounds."""

    name = "Product Sign Contradiction"
    tier = 2

    def matches(self, ctx: ContradictionContext) -> bool:
        """Check if the contradiction context represents a product sign contradiction.

        Args:
            ctx: The contradiction context to test.

        Returns:
            True if the core asserts a product comparison to 0 that disagrees with the sign
            guarantees of its component variables, otherwise False.
        """
        bounds = extract_bounds(ctx.core)
        for left, right, op, value in extract_product_const_comparisons(ctx.core):
            if value != 0:
                continue
            left_bounds = bounds.get(left)
            right_bounds = bounds.get(right)
            if left_bounds is None or right_bounds is None:
                continue

            same_sign_strict = (
                _strictly_positive(left_bounds) and _strictly_positive(right_bounds)
            ) or (_strictly_negative(left_bounds) and _strictly_negative(right_bounds))
            same_sign_nonzero = (_nonnegative(left_bounds) and _nonnegative(right_bounds)) or (
                _nonpositive(left_bounds) and _nonpositive(right_bounds)
            )
            opposite_sign_strict = (
                _strictly_positive(left_bounds) and _strictly_negative(right_bounds)
            ) or (_strictly_negative(left_bounds) and _strictly_positive(right_bounds))
            opposite_sign_nonzero = (_nonnegative(left_bounds) and _nonpositive(right_bounds)) or (
                _nonpositive(left_bounds) and _nonnegative(right_bounds)
            )

            if op in ("<=", "<") and (same_sign_strict or (op == "<" and same_sign_nonzero)):
                return True
            if op in (">=", ">") and (
                opposite_sign_strict or (op == ">" and opposite_sign_nonzero)
            ):
                return True

        return False
