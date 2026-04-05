# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Property types for PySyMex property-based verification.

Defines the core data types: PropertyKind, ProofStatus, PropertySpec, PropertyProof.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass, field
from enum import Enum, auto

import z3


class PropertyKind(Enum):
    """Categories of mathematical properties."""

    COMMUTATIVITY = auto()
    ASSOCIATIVITY = auto()
    DISTRIBUTIVITY = auto()
    IDENTITY = auto()
    INVERSE = auto()
    IDEMPOTENCE = auto()
    ABSORPTION = auto()
    MONOTONIC_INC = auto()
    MONOTONIC_DEC = auto()
    STRICT_MONOTONIC_INC = auto()
    STRICT_MONOTONIC_DEC = auto()
    LOWER_BOUND = auto()
    UPPER_BOUND = auto()
    BOUNDED = auto()
    NON_NEGATIVE = auto()
    POSITIVE = auto()
    PRESERVES_SIGN = auto()
    EVEN_FUNCTION = auto()
    ODD_FUNCTION = auto()
    EQUIVALENCE = auto()
    REFINEMENT = auto()
    TERMINATION = auto()
    DETERMINISTIC = auto()
    INJECTIVE = auto()
    SURJECTIVE = auto()
    BIJECTIVE = auto()


class ProofStatus(Enum):
    """Status of a property proof."""

    PROVEN = auto()
    DISPROVEN = auto()
    UNKNOWN = auto()
    TIMEOUT = auto()
    CONDITIONAL = auto()


@dataclass
class PropertySpec:
    """Specification of a property to verify."""

    kind: PropertyKind
    name: str
    description: str = ""
    constraints: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    lower_bound: z3.ExprRef | None = None
    upper_bound: z3.ExprRef | None = None
    equivalent_expr: z3.ExprRef | None = None


@dataclass
class PropertyProof:
    """Result of attempting to prove a property."""

    property: PropertySpec
    status: ProofStatus
    counterexample: dict[str, object] | None = None
    witness: dict[str, object] | None = None
    conditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    time_seconds: float = 0.0

    @builtins.property
    def is_proven(self) -> bool:
        return self.status == ProofStatus.PROVEN

    @builtins.property
    def is_disproven(self) -> bool:
        return self.status == ProofStatus.DISPROVEN

    def format(self) -> str:
        """Format proof result for display."""
        status_symbol = {
            ProofStatus.PROVEN: "✓",
            ProofStatus.DISPROVEN: "✗",
            ProofStatus.UNKNOWN: "?",
            ProofStatus.TIMEOUT: "⏱",
            ProofStatus.CONDITIONAL: "⚠",
        }
        result = f"{status_symbol.get(self.status, '?')} {self.property.name}: {self.status.name}"
        if self.counterexample:
            result += f"\n  Counterexample: {self.counterexample}"
        if self.conditions:
            result += f"\n  Conditions: {len(self.conditions)} additional constraints"
        return result


__all__ = [
    "ProofStatus",
    "PropertyKind",
    "PropertyProof",
    "PropertySpec",
]
