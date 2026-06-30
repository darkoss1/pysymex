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

"""Finite quantifier lowering policy and unsupported-state records."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from pysymex._internal.contracts.ir.evidence import UnsupportedReason

if TYPE_CHECKING:
    from collections.abc import Mapping


def _empty_symbolic_ranges() -> Mapping[str, ConcreteRange]:
    """Return the immutable empty symbolic-bound policy map."""
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ConcreteRange:
    """Inclusive integer value range for a symbolic bound expression."""

    lower: int
    upper: int

    def __post_init__(self) -> None:
        """Reject impossible policy ranges early."""
        if self.upper < self.lower:
            msg = "ConcreteRange upper bound must be greater than or equal to lower"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class QuantifierLoweringPolicy:
    """Controls finite quantifier expansion and native Z3 fallback."""

    max_expansion: int | None = None
    symbolic_ranges: Mapping[str, ConcreteRange] = field(default_factory=_empty_symbolic_ranges)
    allow_native_z3: bool = False

    def __post_init__(self) -> None:
        """Freeze caller-provided maps and validate expansion limits."""
        if self.max_expansion is not None and self.max_expansion < 0:
            msg = "max_expansion must be non-negative"
            raise ValueError(msg)
        object.__setattr__(
            self,
            "symbolic_ranges",
            MappingProxyType(dict(self.symbolic_ranges)),
        )


class QuantifierLoweringError(ValueError):
    """Raised when a quantifier has no sound lowering under the active policy."""

    unsupported_reason: UnsupportedReason

    def __init__(
        self,
        message: str,
        *,
        unsupported_reason: UnsupportedReason = UnsupportedReason.UNBOUNDED_QUANTIFIER,
    ) -> None:
        """Create a lowering error with an evidence-compatible reason."""
        super().__init__(message)
        self.unsupported_reason = unsupported_reason


DEFAULT_QUANTIFIER_LOWERING_POLICY = QuantifierLoweringPolicy()
