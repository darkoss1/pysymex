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

"""Structured results produced by collection and subscript lowering.

Carries stack values, path constraints, feasible exception conditions, heap
updates, and degradation pass tags back to common opcode handlers. Does not
perform lowering itself; see :mod:`pysymex._internal.execution.opcodes.common.lowering`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pysymex._internal.core.constants import Z3_FALSE

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.typing.protocols import StackValue


def _empty_constraints() -> list[z3.BoolRef]:
    """Return the default empty constraint list for lowered values."""
    return []


def _empty_heap_updates() -> list[tuple[int, StackValue]]:
    """Return the default empty heap-update list for lowered values."""
    return []


def _empty_degraded_passes() -> list[str]:
    """Return the default empty degradation tag list for lowered values."""
    return []


# Reported when subscript lowering falls back to unsupported abstraction.
UNSUPPORTED_SUBSCRIPT_ABSTRACTION = "unsupported_subscript_abstraction"


@dataclass(frozen=True, slots=True)
class LoweredValue:
    """Value plus constraints emitted while lowering an opcode."""

    value: StackValue
    constraints: list[z3.BoolRef] = field(default_factory=_empty_constraints)
    exception_condition: z3.BoolRef = Z3_FALSE
    heap_updates: list[tuple[int, StackValue]] = field(default_factory=_empty_heap_updates)
    degraded_passes: list[str] = field(default_factory=_empty_degraded_passes)


@dataclass(frozen=True, slots=True)
class LoweredListBuild:
    """Heap handle, backing list storage, and optional alias updates from BUILD_LIST."""

    handle: SymbolicObject
    storage: SymbolicList
    heap_updates: list[tuple[int, StackValue]] = field(default_factory=_empty_heap_updates)
