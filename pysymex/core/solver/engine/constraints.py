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

"""Constraint normalization helpers for solver entrypoints."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex.core.solver.independence.protocols import has_to_z3


def as_bool_constraint(value: object) -> z3.BoolRef | None:
    """Return a Boolean Z3 view of ``value``, or ``None`` if unsupported."""
    if isinstance(value, z3.BoolRef):
        return value
    if has_to_z3(value):
        expr = value.to_z3()
        if isinstance(expr, z3.BoolRef):
            return expr
    return None


def normalize_constraint_iterable(values: Iterable[object]) -> list[z3.BoolRef]:
    """Return Boolean-normalizable candidates, omitting unsupported values.

    Notes:
        Structured solver entrypoints compare input and output lengths so
        omitted candidates become ``UNKNOWN`` rather than a definitive result.
    """
    constraints: list[z3.BoolRef] = []
    for value in values:
        normalized = as_bool_constraint(value)
        if normalized is not None:
            constraints.append(normalized)
    return constraints
