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

"""Public ``forall``, ``exists``, and ``exists_unique`` factory helpers.

Build :class:`~pysymex.contracts.quantifiers.types.Quantifier` values for use inside string
or programmatic contract specifications. Compilation and checking happen elsewhere.
"""

from __future__ import annotations

from pysymex.contracts.quantifiers.parser import QuantifierParser
from pysymex.contracts.quantifiers.types import Quantifier


def _condition_text(condition: object) -> str:
    """Require the string body representation implemented by the parser."""
    if not isinstance(condition, str):
        raise TypeError("Quantifier factory conditions must be string predicates")
    return condition


def forall(
    var: str,
    range_spec: tuple[int, int] | str,
    condition: str,
) -> Quantifier:
    """Create a universal quantifier clause metadata block.

    Args:
        var: Bound variable name (e.g. ``"i"``).
        range_spec: Range boundaries, either as a tuple of ``(lower, upper)``
            representing ``lower <= var < upper``, or as a custom range string
            (e.g., ``"0 <= i < len(x)"``).
        condition: The inner condition string constraint that must hold.

    Returns:
        A structured ``Quantifier`` representing the universal expression.

    Raises:
        ValueError: If range or condition parsing fails.
    """
    parser = QuantifierParser()
    if isinstance(range_spec, tuple):
        lower, upper = range_spec
        range_str = f"{lower} <= {var} < {upper}"
    else:
        range_str = range_spec
    cond_str = _condition_text(condition)
    text = f"forall({var}, {range_str}, {cond_str})"
    result = parser.parse(text)
    if result is None:
        raise ValueError(f"Failed to parse universal quantifier: {text}")
    return result


def exists(
    var: str,
    range_spec: tuple[int, int] | str,
    condition: str,
) -> Quantifier:
    """Create an existential quantifier clause metadata block.

    Args:
        var: Bound variable name (e.g. ``"i"``).
        range_spec: Range boundaries, either as a tuple of ``(lower, upper)``
            representing ``lower <= var < upper``, or as a custom range string
            (e.g., ``"0 <= i < len(x)"``).
        condition: The inner condition string constraint that must hold.

    Returns:
        A structured ``Quantifier`` representing the existential expression.

    Raises:
        ValueError: If range or condition parsing fails.
    """
    parser = QuantifierParser()
    if isinstance(range_spec, tuple):
        lower, upper = range_spec
        range_str = f"{lower} <= {var} < {upper}"
    else:
        range_str = range_spec
    cond_str = _condition_text(condition)
    text = f"exists({var}, {range_str}, {cond_str})"
    result = parser.parse(text)
    if result is None:
        raise ValueError(f"Failed to parse existential quantifier: {text}")
    return result


def exists_unique(
    var: str,
    range_spec: tuple[int, int] | str,
    condition: str,
) -> Quantifier:
    """Create a unique existential quantifier clause metadata block.

    Args:
        var: Bound variable name (e.g. ``"i"``).
        range_spec: Range boundaries, either as a tuple of ``(lower, upper)``
            representing ``lower <= var < upper``, or as a custom range string
            (e.g., ``"0 <= i < len(x)"``).
        condition: The inner condition string constraint that must hold.

    Returns:
        A structured ``Quantifier`` representing the unique existential expression.

    Raises:
        ValueError: If range or condition parsing fails.
    """
    parser = QuantifierParser()
    if isinstance(range_spec, tuple):
        lower, upper = range_spec
        range_str = f"{lower} <= {var} < {upper}"
    else:
        range_str = range_spec
    cond_str = _condition_text(condition)
    text = f"exists!({var}, {range_str}, {cond_str})"
    result = parser.parse(text)
    if result is None:
        raise ValueError(f"Failed to parse unique existential quantifier: {text}")
    return result


__all__ = ["exists", "exists_unique", "forall"]
