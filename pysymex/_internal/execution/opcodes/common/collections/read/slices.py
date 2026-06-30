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

"""Concrete retained-slice lowering for ``BINARY_SUBSCR`` reads."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.solver.slices import materialize_concrete_slice
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.execution.opcodes.common.lowering.collections.lowerer import (
    CollectionLowerer,
)
from pysymex._internal.execution.opcodes.common.lowering.subscripts import (
    to_stack_value,
)
from pysymex._internal.execution.opcodes.common.lowering.types import LoweredValue
from pysymex._internal.core.types.containers.sequence_precision import (
    slice_concrete_backed_sequence,
)

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.typing.protocols import StackValue


def lower_concrete_built_slice(
    container: object,
    carrier: SymbolicValue,
    constraints: list[z3.BoolRef],
    pc: int,
) -> LoweredValue | None:
    """Lower a subscript read when slice bounds are concrete on this path."""
    concrete_slice = materialize_concrete_slice(carrier, constraints)
    if concrete_slice is None:
        return None
    if isinstance(container, SymbolicList):
        retained = slice_concrete_backed_sequence(container, concrete_slice, constraints)
        if retained is None:
            return None
        if getattr(retained, "_type", None) == "tuple":
            return LoweredValue(retained)
        concrete_items = retained.concrete_items
        if concrete_items is None:
            return None
        items = cast("list[StackValue]", concrete_items)
        built = CollectionLowerer(pc).build_list(items)
        return LoweredValue(
            built.handle,
            heap_updates=[*built.heap_updates, (built.handle.address, built.storage)],
        )
    if isinstance(container, SymbolicString):
        retained_string = _slice_symbolic_string(container, concrete_slice)
        if retained_string is not None:
            return LoweredValue(retained_string)
    if isinstance(container, SymbolicBytes):
        retained_bytes = _slice_symbolic_bytes(container, concrete_slice, pc)
        if retained_bytes is not None:
            return LoweredValue(retained_bytes)
    if isinstance(container, (list, tuple, str, bytes)):
        concrete_container = cast("list[object] | tuple[object, ...] | str | bytes", container)
        return LoweredValue(to_stack_value(concrete_container[concrete_slice]))
    return None


def _slice_symbolic_string(value: SymbolicString, key: slice) -> SymbolicString | None:
    """Return an exact symbolic string slice for unit-step concrete bounds."""
    return value.slice_value(key)


def _slice_symbolic_bytes(value: SymbolicBytes, key: slice, _pc: int) -> SymbolicBytes | None:
    """Return an exact symbolic bytes slice for unit-step BUILD_SLICE bounds."""
    return value.slice_value(key)
