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

"""Domain types for arithmetic safety analysis (findings, ranges, configs)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum, auto

import z3


def empty_counterexample() -> dict[str, object]:
    """Create a typed empty counterexample map."""
    return {}


def empty_constraints() -> list[z3.BoolRef]:
    """Create a typed empty constraint list."""
    return []


class ArithmeticIssueKind(Enum):
    """Types of arithmetic safety issues."""

    SIGNED_OVERFLOW = auto()
    SIGNED_UNDERFLOW = auto()
    UNSIGNED_OVERFLOW = auto()
    UNSIGNED_UNDERFLOW = auto()
    DIVISION_BY_ZERO = auto()
    MODULO_BY_ZERO = auto()
    DIVISION_OVERFLOW = auto()
    FLOAT_NAN = auto()
    FLOAT_INFINITY = auto()
    FLOAT_PRECISION_LOSS = auto()
    FLOAT_DENORMAL = auto()
    SHIFT_OVERFLOW = auto()
    NEGATIVE_SHIFT = auto()
    TRUNCATION = auto()
    SIGN_LOSS = auto()
    POWER_OVERFLOW = auto()
    ABS_OVERFLOW = auto()


@dataclass
class ArithmeticIssue:
    """Represents a detected arithmetic safety issue."""

    kind: ArithmeticIssueKind
    message: str
    location: str | None = None
    line_number: int | None = None
    constraints: Sequence[z3.BoolRef] = field(default_factory=empty_constraints)
    counterexample: dict[str, object] = field(default_factory=empty_counterexample)
    severity: str = "error"

    def format(self) -> str:
        """Format issue for display."""
        loc = f" at line {self.line_number}" if self.line_number else ""
        ce = ""
        if self.counterexample:
            ce = " | Counterexample: " + ", ".join(
                f"{k}={v}" for k, v in self.counterexample.items()
            )
        return f"[{self.kind.name}]{loc}: {self.message}{ce}"
