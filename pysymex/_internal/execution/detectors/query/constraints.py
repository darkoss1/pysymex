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

"""Constraint normalization and inconclusive-prefix matching for detector queries."""

from __future__ import annotations

import z3

from pysymex._internal.core.solver.constraints.literals import exact_bool_literal


def should_try_inconclusive_prefix_witness(
    *,
    constraints: list[z3.BoolRef],
    inconclusive_prefix_len: int | None,
) -> bool:
    """Return whether a verified witness should precede a repeated hard solver query."""
    return inconclusive_prefix_len is not None and len(constraints) > inconclusive_prefix_len


def shared_inconclusive_prefix_len(
    constraints: list[z3.BoolRef],
    inconclusive_path_prefix: tuple[z3.BoolRef, ...] | None,
) -> int | None:
    """Return the non-trivial inconclusive-prefix length matched by a query."""
    if inconclusive_path_prefix is None:
        return None
    expected_prefix = tuple(
        constraint
        for constraint in inconclusive_path_prefix
        if exact_bool_literal(constraint) is not True
    )
    if not expected_prefix:
        return None
    prefix_len = len(expected_prefix)
    if len(constraints) < prefix_len:
        return None
    for expected, actual in zip(expected_prefix, constraints[:prefix_len], strict=True):
        if expected is actual:
            continue
        if not z3.eq(expected, actual):
            return None
    return prefix_len


def matching_known_sat_path_prefix_len(
    constraints: list[z3.BoolRef],
    known_sat_path_prefix: tuple[z3.BoolRef, ...] | None,
) -> int | None:
    """Return the known-SAT prefix length matched by a normalized detector query."""
    if known_sat_path_prefix is None:
        return None
    expected_prefix = tuple(
        constraint
        for constraint in known_sat_path_prefix
        if exact_bool_literal(constraint) is not True
    )
    if not expected_prefix:
        return None
    prefix_len = len(expected_prefix)
    if len(constraints) < prefix_len:
        return None
    for expected, actual in zip(expected_prefix, constraints[:prefix_len], strict=True):
        if expected is actual:
            continue
        if not z3.eq(expected, actual):
            return None
    return prefix_len


def canonicalize_detector_query_constraints(
    constraints: list[z3.BoolRef],
) -> bool | list[z3.BoolRef]:
    """Drop literal truths and short-circuit literal falsehoods in detector queries."""
    if not constraints:
        return True

    nontrivial_constraints_reversed: list[z3.BoolRef] = []
    for constraint in reversed(constraints):
        literal = exact_bool_literal(constraint)
        if literal is False:
            return False
        if literal is not True:
            nontrivial_constraints_reversed.append(constraint)
    if not nontrivial_constraints_reversed:
        return True
    nontrivial_constraints_reversed.reverse()
    return nontrivial_constraints_reversed
