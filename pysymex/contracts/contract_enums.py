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

"""Enumerations for contract kinds, outcomes, severity, and injection sites.

Shared labels used by :mod:`pysymex.contracts.types`, runtime injection, and
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
        ASSERT: Inline assertion at the current program point.
    """

    REQUIRES = auto()
    ENSURES = auto()
    INVARIANT = auto()
    LOOP_INVARIANT = auto()
    ASSUMES = auto()
    ASSIGNS = auto()
    PURE = auto()
    ASSERT = auto()


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


class Severity(Enum):
    """User-facing severity for a contract clause violation.

    Members:
        ERROR: Report as a hard contract failure.
        WARNING: Report as a reviewable contract warning.
    """

    ERROR = auto()
    WARNING = auto()


class InjectionPoint(Enum):
    """VM hook categories that trigger contract checks.

    Injection runs in the executor instruction loop; contracts are not woven
    into rewritten bytecode.

    Members:
        FRAME_ENTRY: Function entry (``RESUME`` on 3.11+, else first ``LOAD_FAST``).
        FRAME_EXIT: Function exit (``RETURN_VALUE``, ``RETURN_CONST``).
        STORE_LOCAL: Local assignment (``STORE_FAST``, ``STORE_DEREF``).
        STORE_ATTR: Attribute or element assignment (``STORE_ATTR``, ``STORE_SUBSCR``).
        CALL_SITE: Call dispatch (``CALL``, ``CALL_FUNCTION_EX``).
    """

    FRAME_ENTRY = "RESUME"
    FRAME_EXIT = "RETURN_VALUE"
    STORE_LOCAL = "STORE_FAST"
    STORE_ATTR = "STORE_ATTR"
    CALL_SITE = "CALL"


class EffectKind(Enum):
    """Side-effect classification from ``@pure`` / ``@assigns`` metadata.

    Members:
        PURE: No modeled writes.
        READS: Reads declared locations only.
        WRITES: May write declared locations (default when unspecified).
    """

    PURE = auto()
    READS = auto()
    WRITES = auto()
