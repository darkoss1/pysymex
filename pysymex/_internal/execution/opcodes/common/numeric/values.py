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

"""Symbolic numeric value construction and havoc result helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.numeric.fallbacks import unsupported_numeric_event
from pysymex._internal.execution.opcodes.common.numeric.labels import (
    UNSUPPORTED_NUMERIC_ABSTRACTION,
)

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState


def extract_non_negative_masked_value(
    left: SymbolicValue,
    right: SymbolicValue,
) -> tuple[int, SymbolicValue] | None:
    """Extract a concrete non-negative mask and its paired symbolic operand."""
    left_constant = extract_concrete_int(left)
    if left_constant is not None and left_constant >= 0:
        return left_constant, right
    right_constant = extract_concrete_int(right)
    if right_constant is not None and right_constant >= 0:
        return right_constant, left
    return None


def extract_concrete_int(value: SymbolicValue) -> int | None:
    """Extract a concrete integer or boolean value when available."""
    constant = value.value
    if isinstance(constant, bool):
        return int(constant)
    if isinstance(constant, int):
        return constant
    return None


def fresh_symbolic_int(name: str) -> SymbolicValue:
    """Create a fresh symbolic integer result."""
    symbolic, _ = SymbolicValue.symbolic_int(name)
    return symbolic


def make_int_value(
    *,
    name: str,
    expr: z3.ArithRef,
    min_val: int | None = None,
    max_val: int | None = None,
) -> SymbolicValue:
    """Create an integer-typed ``SymbolicValue`` for an exact numeric result."""
    return SymbolicValue(
        _name=name,
        z3_int=expr,
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_float=Z3_FALSE,
        affinity_type="int",
        min_val=min_val,
        max_val=max_val,
    )


def is_int_like(value: SymbolicValue) -> bool:
    """Return whether the symbolic value is explicitly integer-typed."""
    return value.affinity_type in {"int", "bool"}


def push_havoc_result(state: VMState, name: str) -> OpcodeResult:
    """Push a fresh generic symbolic value for unsupported arithmetic cases."""
    fallback_event = unsupported_numeric_event(
        state=state,
        reason=f"unsupported numeric operation {name!r} produced a havoc value",
    )
    value, constraint = SymbolicValue.symbolic(name)
    state = state.add_constraint(constraint)
    state = state.push(value)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[UNSUPPORTED_NUMERIC_ABSTRACTION],
        fallback_events=[fallback_event],
    )
