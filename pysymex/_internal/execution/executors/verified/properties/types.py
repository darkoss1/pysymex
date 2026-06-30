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

"""Property proof types used by the verified executor."""

from __future__ import annotations

import builtins
from dataclasses import dataclass, field
from enum import Enum, auto

import z3


class PropertyKind(Enum):
    """Categories currently emitted by Verify property checks."""

    MONOTONIC_INC = auto()
    BOUNDED = auto()
    POSITIVE = auto()


class ProofStatus(Enum):
    """Status of a property proof."""

    PROVEN = auto()
    DISPROVEN = auto()
    UNKNOWN = auto()
    TIMEOUT = auto()
    CONDITIONAL = auto()


class ProofReason(Enum):
    """Machine-readable reason for non-definite or diagnostic proof outcomes."""

    SOLVER_UNKNOWN = auto()
    ELAPSED_TIMEOUT = auto()
    QUERY_EXCEPTION = auto()
    MISSING_COUNTEREXAMPLE_MODEL = auto()
    INCOMPLETE_COUNTEREXAMPLE = auto()


@dataclass
class PropertySpec:
    """Specification for one Verify property query."""

    kind: PropertyKind
    name: str
    description: str = ""
    constraints: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])


@dataclass
class PropertyProof:
    """Result of attempting to prove a property."""

    property: PropertySpec
    status: ProofStatus
    counterexample: dict[str, object] | None = None
    witness: dict[str, object] | None = None
    conditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    time_seconds: float = 0.0
    reason: ProofReason | None = None

    @builtins.property
    def is_proven(self) -> bool:
        return self.status == ProofStatus.PROVEN

    @builtins.property
    def is_disproven(self) -> bool:
        return self.status == ProofStatus.DISPROVEN

    def format(self) -> str:
        """Format proof result for display."""
        status_label = {
            ProofStatus.PROVEN: "OK",
            ProofStatus.DISPROVEN: "FAIL",
            ProofStatus.UNKNOWN: "UNKNOWN",
            ProofStatus.TIMEOUT: "TIMEOUT",
            ProofStatus.CONDITIONAL: "CONDITIONAL",
        }
        result = (
            f"[{status_label.get(self.status, 'UNKNOWN')}] {self.property.name}: {self.status.name}"
        )
        if self.counterexample:
            result += f"\n  Counterexample: {self.counterexample}"
        if self.conditions:
            result += f"\n  Conditions: {len(self.conditions)} additional constraints"
        if self.reason is not None:
            result += f"\n  Reason: {self.reason.name}"
        return result
