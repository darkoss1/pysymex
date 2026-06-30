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

"""Sequence bounds evidence for index-error detector queries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.havoc import is_havoc
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.guards import RuntimeObjectGuards

if TYPE_CHECKING:
    import z3


@dataclass(frozen=True, slots=True)
class IndexBoundsEvidence:
    """Derived bounds and reporting metadata for a supported sequence shape."""

    lower_bound: z3.ArithRef
    upper_bound: z3.ArithRef
    container_name: str
    confidence: float


def unwrap_symbolic_sequence(container: object) -> object:
    """Return concrete sequence payloads stored in constant symbolic values."""
    if not isinstance(container, SymbolicValue):
        return container
    value: object = container.value
    if (
        RuntimeObjectGuards.list(value)
        or RuntimeObjectGuards.tuple(value)
        or isinstance(value, (SymbolicTuple, str, bytes, bytearray, range))
    ):
        return value
    return container


def index_bounds_evidence(
    container: object,
    index: SymbolicValue,
) -> IndexBoundsEvidence | None:
    """Return sequence bounds and confidence metadata for supported containers."""
    if isinstance(container, SymbolicList):
        return IndexBoundsEvidence(
            lower_bound=-container.z3_len,
            upper_bound=container.z3_len,
            container_name=container.name,
            confidence=index_confidence(index, container_is_havoc=is_havoc(container)),
        )
    if isinstance(container, SymbolicTuple):
        return concrete_length_bounds(len(container), container.name, index)
    if isinstance(container, SymbolicString):
        return IndexBoundsEvidence(
            lower_bound=-container.z3_len,
            upper_bound=container.z3_len,
            container_name=container.name,
            confidence=index_confidence(index),
        )
    if isinstance(container, (str, bytes, bytearray, range)):
        return concrete_length_bounds(len(container), type(container).__name__, index)
    if RuntimeObjectGuards.list(container):
        return concrete_length_bounds(len(container), "list", index)
    if RuntimeObjectGuards.tuple(container):
        return concrete_length_bounds(len(container), "list", index)
    return None


def concrete_length_bounds(
    concrete_len: int,
    container_name: str,
    index: SymbolicValue,
) -> IndexBoundsEvidence:
    """Return bounds evidence for concrete-length sequence containers."""
    return IndexBoundsEvidence(
        lower_bound=ConstraintValues.int(-concrete_len),
        upper_bound=ConstraintValues.int(concrete_len),
        container_name=container_name,
        confidence=index_confidence(index),
    )


def index_confidence(index: SymbolicValue, *, container_is_havoc: bool = False) -> float:
    """Return the existing confidence value for index-bounds evidence."""
    if is_havoc(index) or container_is_havoc:
        return 0.5
    if hasattr(index, "affinity_type") and index.affinity_type == "int":
        return 0.9
    return 1.0
