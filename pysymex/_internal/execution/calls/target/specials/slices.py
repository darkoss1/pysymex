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

"""Slice helper callable adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def dispatch_slice_indices_call(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Apply supported ``slice.indices`` callables for non-negative lengths."""
    from pysymex._internal.models.builtins.conversions.numeric import SliceIndicesCallable

    if not isinstance(func_obj, SliceIndicesCallable) or len(args) != 1 or kwargs:
        return None

    length: int | z3.ArithRef | None = None
    if isinstance(args[0], int) and not isinstance(args[0], bool):
        length = args[0]
    elif (
        isinstance(args[0], SymbolicValue)
        and args[0].affinity_type == "int"
        and args[0].name.startswith("len_")
    ):
        length = args[0].z3_int
    if isinstance(length, int) and length < 0:
        length = None
    if length is None:
        return None

    state = state.push(coerce_call_stack_value(func_obj.for_nonnegative_length(length)))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
