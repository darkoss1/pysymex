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

"""Shared cache records and protocols for solver APIs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.solver.engine.results import SolverResult

CACHE_CONTEXT_MASK = (1 << 128) - 1
UNSAT_SUBSET_CACHE_MAX_ENTRIES = 128
CONSTRAINT_FINGERPRINT_CACHE_MAX_ENTRIES = 4096


@dataclass(frozen=True, slots=True)
class CheckCacheEntry:
    """Cached low-level check result with exact context collision validation."""

    context: tuple[z3.BoolRef, ...]
    assumptions: tuple[z3.BoolRef, ...]
    result: SolverResult


@dataclass(frozen=True, slots=True)
class AstTranslationCacheEntry:
    """Cached BoolRef translated into this solver's Z3 context."""

    source: z3.BoolRef
    translated: z3.BoolRef


@dataclass(frozen=True, slots=True)
class UnsatSubsetCacheEntry:
    """Cached UNSAT conjunction usable as evidence for later supersets."""

    constraints: tuple[z3.BoolRef, ...]
    constraint_hashes: tuple[int, ...]
    constraint_hash_counts: tuple[tuple[int, int], ...]


class TranslatableZ3Expr(Protocol):
    """Z3 expression surface for context translation."""

    def translate(self, target: z3.Context) -> z3.ExprRef:
        """Return this expression translated into ``target``."""
        ...
