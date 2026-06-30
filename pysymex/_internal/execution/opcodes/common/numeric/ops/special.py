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

"""Power, shift, and bitwise numeric ``BINARY_OP`` semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.scalars.value.scalar_ops import Z3_OP_BV2INT, ScalarValueOps
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.numeric.fallbacks import (
    symbolic_power_event,
    symbolic_shift_event,
)
from pysymex._internal.execution.opcodes.common.numeric.intervals import (
    extract_interval,
    piecewise_exact_power,
    piecewise_exact_shift_left,
    piecewise_exact_shift_right,
)
from pysymex._internal.execution.opcodes.common.numeric.labels import (
    SYMBOLIC_POWER_ABSTRACTION,
    SYMBOLIC_SHIFT_ABSTRACTION,
)
from pysymex._internal.execution.opcodes.common.numeric.values import (
    extract_concrete_int,
    extract_non_negative_masked_value,
    fresh_symbolic_int,
    is_int_like,
    make_int_value,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.scalars.values import SymbolicValue


def handle_power_op(state: VMState, left: SymbolicValue, right: SymbolicValue) -> OpcodeResult:
    """Execute exponentiation with bounded exactness and explicit abstraction."""
    concrete_exponent = extract_concrete_int(right)
    if concrete_exponent is not None:
        try:
            result = left**right
        except ZeroDivisionError:
            return OpcodeResult.terminate()
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    interval = extract_interval(state.path_constraints.to_list(), right.z3_int)
    if interval.has_finite_non_negative_range() and is_int_like(left):
        assert interval.lower is not None
        assert interval.upper is not None
        result = make_int_value(
            name=f"pow_{state.pc}",
            expr=piecewise_exact_power(left.z3_int, right.z3_int, interval.lower, interval.upper),
        )
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    abstract = fresh_symbolic_int(f"pow_{state.pc}")
    fallback_event = symbolic_power_event(
        state=state,
        reason="symbolic exponent range is too broad for exact power modeling",
    )
    state = state.push(abstract)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[SYMBOLIC_POWER_ABSTRACTION],
        fallback_events=[fallback_event],
    )


def handle_shift_op(
    state: VMState,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Execute shift operations with exact concrete semantics or bounded abstraction."""
    concrete_shift = extract_concrete_int(right)
    if concrete_shift is not None:
        if concrete_shift < 0:
            return OpcodeResult.terminate()
        factor = 1 << concrete_shift
        if op_symbol == "<<":
            expr = left.z3_int * ConstraintValues.int(factor)
        else:
            expr = ScalarValueOps.py_floor_div(left.z3_int, ConstraintValues.int(factor))
        min_val, max_val = _shift_bounds(left, concrete_shift, op_symbol)
        result = make_int_value(
            name=f"shift_{state.pc}",
            expr=expr,
            min_val=min_val,
            max_val=max_val,
        )
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    interval = extract_interval(state.path_constraints.to_list(), right.z3_int)
    if interval.has_finite_non_negative_range():
        assert interval.lower is not None
        assert interval.upper is not None
        if op_symbol == "<<":
            expr = piecewise_exact_shift_left(
                left.z3_int,
                right.z3_int,
                interval.lower,
                interval.upper,
            )
        else:
            expr = piecewise_exact_shift_right(
                left.z3_int,
                right.z3_int,
                interval.lower,
                interval.upper,
            )
        result = make_int_value(name=f"shift_{state.pc}", expr=expr)
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    abstract = fresh_symbolic_int(f"shift_{state.pc}")
    fallback_event = symbolic_shift_event(
        state=state,
        reason=f"symbolic shift count for {op_symbol!r} is too broad for exact modeling",
    )
    state = state.push(abstract)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[SYMBOLIC_SHIFT_ABSTRACTION],
        fallback_events=[fallback_event],
    )


def _shift_bounds(
    value: SymbolicValue,
    shift: int,
    op_symbol: str,
) -> tuple[int | None, int | None]:
    """Return exact monotonic bounds for a concrete non-negative shift count."""
    min_value = value.min_val
    max_value = value.max_val
    if not isinstance(min_value, int) or not isinstance(max_value, int):
        return None, None
    if op_symbol == "<<":
        factor = 1 << shift
        return min_value * factor, max_value * factor
    return min_value >> shift, max_value >> shift


def _is_low_bits_mask(mask: int) -> bool:
    """Return whether *mask* is ``2**n - 1`` for some non-negative width."""
    return mask >= 0 and mask & (mask + 1) == 0


def _is_bitvector_backed_int_expr(expr: z3.ArithRef) -> bool:
    """Return whether *expr* is already an integer view over a bit-vector expression."""
    try:
        return expr.decl().kind() == Z3_OP_BV2INT and expr.num_args() == 1
    except (AttributeError, z3.Z3Exception):
        return False


def _low_bits_mask_expr(value: SymbolicValue, mask: int) -> z3.ArithRef:
    """Return an exact expression for ``value & mask`` when *mask* selects low bits."""
    cached_bitvector = getattr(value, "_bv_cache", None)
    if isinstance(cached_bitvector, z3.BitVecRef):
        bitvector = cached_bitvector
    elif _is_bitvector_backed_int_expr(value.z3_int):
        bitvector = ScalarValueOps.int_to_bv(value.z3_int)
    else:
        return value.z3_int % ConstraintValues.int(mask + 1)

    width = max(1, mask.bit_length())
    if bitvector.size() > width:
        bitvector = z3.Extract(width - 1, 0, bitvector)
    elif bitvector.size() < width:
        bitvector = z3.ZeroExt(width - bitvector.size(), bitvector)
    return z3.BV2Int(bitvector, is_signed=False)


def handle_bitwise_op(
    state: VMState,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Execute bitwise operations with exact concrete cases and explicit abstraction."""
    left_constant = extract_concrete_int(left)
    right_constant = extract_concrete_int(right)
    if left_constant is not None and right_constant is not None:
        if op_symbol == "&":
            result = left & right
        elif op_symbol == "|":
            result = left | right
        else:
            result = left ^ right
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    if op_symbol == "&":
        masked = extract_non_negative_masked_value(left, right)
        if masked is not None:
            mask, value = masked
            if _is_low_bits_mask(mask):
                expr = _low_bits_mask_expr(value, mask)
            else:
                width = max(1, mask.bit_length())
                expr = z3.BV2Int(
                    z3.Int2BV(value.z3_int, width) & ConstraintValues.bitvec(mask, width),
                    is_signed=False,
                )
            result = make_int_value(name=f"mask_{state.pc}", expr=expr, min_val=0, max_val=mask)
            state = state.push(result)
            return OpcodeResult.continue_with(state.advance_pc())

    if op_symbol == "&":
        result = left & right
    elif op_symbol == "|":
        result = left | right
    else:
        result = left ^ right
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())
