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

"""Frontend-neutral predicate IR records.

Predicate IR stores source-level predicate structure before path-local lowering
turns it into Z3 formulas. It contains no solver calls and does not decide
verification outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PredicateIRKind(Enum):
    """Supported predicate IR node families."""

    EXPRESSION = "expression"
    QUANTIFIER = "quantifier"


class QuantifierPredicateKind(Enum):
    """Source-level quantifier predicate families."""

    FORALL = "forall"
    EXISTS = "exists"
    UNIQUE = "exists!"
    COUNT = "count"


@dataclass(frozen=True, slots=True)
class PredicateIR:
    """Base predicate IR record with original source text."""

    kind: PredicateIRKind
    source: str


@dataclass(frozen=True, slots=True)
class QuantifierPredicateIR:
    """Source-level quantifier predicate before Z3 lowering."""

    source: str
    quantifier_kind: QuantifierPredicateKind
    variable: str
    bound_source: str
    body_source: str

    @property
    def kind(self) -> PredicateIRKind:
        """Return the predicate family for this IR record."""
        return PredicateIRKind.QUANTIFIER


__all__ = [
    "PredicateIR",
    "PredicateIRKind",
    "QuantifierPredicateIR",
    "QuantifierPredicateKind",
]
