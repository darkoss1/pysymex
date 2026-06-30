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

"""Enumerations for contract kinds, outcomes, severity, and effect policies.

Shared labels used by :mod:`pysymex._internal.contracts.types`, runtime injection, and
reporting. Contains no compilation, solver, or VM logic.
"""

from __future__ import annotations

from enum import Enum, auto


class ContractKind(Enum):
    """Classification of a single contract clause.

    Each kind maps to bytecode injection points used by the executor to decide
    when a clause is compiled and checked.

    Members:
        REQUIRES: Precondition checked at function entry.
        ENSURES: Postcondition checked at function return.
        INVARIANT: Class-level invariant obligation.
        LOOP_INVARIANT: Loop invariant checked at a fixed program counter.
        ASSUMES: Assumption asserted on the current path without a proof obligation.
        ASSIGNS: Frame condition listing modifiable locations.
        PURE: Declared absence of side effects.
    """

    REQUIRES = auto()
    ENSURES = auto()
    INVARIANT = auto()
    LOOP_INVARIANT = auto()
    ASSUMES = auto()
    ASSIGNS = auto()
    PURE = auto()


class VerificationResult(Enum):
    """Outcome of one contract check on the current path.

    Values reflect a single solver query (or compilation step), not global
    correctness of the program.

    Members:
        VERIFIED: The query succeeded under current path constraints and modeling.
        VIOLATED: A satisfying witness was found for the negated obligation.
        UNKNOWN: Solver returned ``unknown`` or the query failed unexpectedly.
        UNSUPPORTED: The predicate or value model could not be compiled soundly.
        UNREACHABLE: Active path constraints contradict a required precondition.
    """

    VERIFIED = auto()
    VIOLATED = auto()
    UNKNOWN = auto()
    UNSUPPORTED = auto()
    UNREACHABLE = auto()


class ContractSeverity(Enum):
    """User-facing severity for a contract clause violation.

    Members:
        ERROR: Report as a hard contract failure.
        WARNING: Report as a reviewable contract warning.
    """

    ERROR = auto()
    WARNING = auto()

class EffectKind(Enum):
    """Side-effect classification from ``@pure`` / ``@assigns`` metadata.

    Members:
        PURE: No modeled writes.
        WRITES: May write declared locations (default when unspecified).
    """

    PURE = auto()
    WRITES = auto()
