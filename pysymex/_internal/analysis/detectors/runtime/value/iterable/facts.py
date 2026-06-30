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

"""Iterable emptiness evidence for min/max ValueError detection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import z3

from pysymex._internal.core.solver.engine.queries import check_sat_result


class EmptyIterableCheckStatus(Enum):
    """Outcome of proving whether an iterable is definitely empty."""

    KNOWN_EMPTY = "known_empty"
    NOT_KNOWN_EMPTY = "not_known_empty"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EmptyIterableCheckResult:
    """Structured evidence for CPython empty-iterable ValueError checks."""

    status: EmptyIterableCheckStatus
    reason: str | None = None

    @staticmethod
    def known_empty(reason: str | None = None) -> EmptyIterableCheckResult:
        """Create a result for a definitely empty iterable."""
        return EmptyIterableCheckResult(EmptyIterableCheckStatus.KNOWN_EMPTY, reason)

    @staticmethod
    def not_known_empty(reason: str) -> EmptyIterableCheckResult:
        """Create a result when definite emptiness is not established."""
        return EmptyIterableCheckResult(EmptyIterableCheckStatus.NOT_KNOWN_EMPTY, reason)

    @staticmethod
    def unknown(reason: str) -> EmptyIterableCheckResult:
        """Create a result for unsupported or solver-inconclusive emptiness checks."""
        return EmptyIterableCheckResult(EmptyIterableCheckStatus.UNKNOWN, reason)


_EMPTY_EXACT_TYPES = {
    list,
    tuple,
    set,
    frozenset,
    dict,
    range,
    str,
    bytes,
    bytearray,
}


def is_known_empty_iterable(value: object, constraints: list[z3.BoolRef]) -> bool:
    """Return True when CPython min/max would see a definitely empty iterable."""
    return (
        is_known_empty_iterable_result(value, constraints).status
        is EmptyIterableCheckStatus.KNOWN_EMPTY
    )


def is_known_empty_iterable_result(
    value: object,
    constraints: list[z3.BoolRef],
) -> EmptyIterableCheckResult:
    """Return structured evidence for definite iterable emptiness."""
    if type(value) in _EMPTY_EXACT_TYPES:
        if not value:
            return EmptyIterableCheckResult.known_empty("concrete_empty")
        return EmptyIterableCheckResult.not_known_empty("concrete_non_empty")

    z3_len = getattr(value, "z3_len", None)
    if isinstance(z3_len, z3.ArithRef):
        non_empty_result = check_sat_result([*constraints, z3_len != 0])
        if non_empty_result.is_unsat:
            return EmptyIterableCheckResult.known_empty("non_empty_unsat")
        if non_empty_result.is_unknown:
            return EmptyIterableCheckResult.unknown("solver_unknown")
        return EmptyIterableCheckResult.not_known_empty("non_empty_feasible")

    return EmptyIterableCheckResult.unknown("length_unavailable")
