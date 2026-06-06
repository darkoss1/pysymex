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

"""BINARY_OP and unary numeric opcode semantics for the common handler layer.

Prefers modeled binary dunders, then :class:`~pysymex.core.types.scalars.values.SymbolicValue`
arithmetic with explicit division-by-zero forking. Power, shift, and bitwise
cases degrade to fresh integers when intervals are too wide, recording abstraction
pass identifiers on the resulting
:class:`~pysymex.execution.dispatch.result.OpcodeResult`.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.bytecode import resolve_binary_op_symbol
from pysymex.core.solver.constraints.hashing import get_bitvec_val
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.scalars.value.helpers import (
    Z3_OP_BV2INT,
    int_to_bv,
)
from pysymex.core.types.scalars.values import py_floor_div
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.numeric.labels import (
    SYMBOLIC_POWER_ABSTRACTION,
    SYMBOLIC_SHIFT_ABSTRACTION,
)
from pysymex.execution.opcodes.common.numeric.helpers import (
    division_by_zero_condition,
    extract_concrete_int,
    extract_non_negative_masked_value,
    fresh_symbolic_int,
    is_int_like,
    jump_to_modeled_exception_handler,
    make_int_value,
    path_is_sat,
    push_havoc_result,
    try_binary_dunder_call,
)
from pysymex.execution.opcodes.common.path_feasibility import path_check_result
from pysymex.execution.opcodes.common.numeric.fallbacks import (
    symbolic_power_event,
    symbolic_shift_event,
)
from pysymex.models.builtins.results import ModelResult
from pysymex.execution.opcodes.common.numeric.intervals import (
    extract_interval,
    piecewise_exact_power,
    piecewise_exact_shift_left,
    piecewise_exact_shift_right,
)
from pysymex.execution.opcodes.common.numeric.type_errors import (
    binary_none_type_error,
    binary_string_type_error,
)
from pysymex.execution.opcodes.common.numeric.unary_positive import (
    continue_unary_positive_value as _continue_unary_positive_value,
    handle_unary_positive as _handle_unary_positive,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
    from pysymex.typing import StackValue


def handle_numeric_binary_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None = None,
) -> OpcodeResult:
    """Execute Python-faithful numeric ``BINARY_OP`` semantics."""
    op_symbol = resolve_binary_op_symbol(instr)
    if not op_symbol:
        state.pop()
        state.pop()
        return push_havoc_result(state, f"binop_havoc_{state.pc}")
    base_op = op_symbol[:-1] if op_symbol.endswith("=") else op_symbol

    right = state.pop()
    left = state.pop()

    if base_op not in {"+", "-", "*", "/", "//", "%", "**", "<<", ">>", "&", "|", "^"}:
        return push_havoc_result(state, f"binop_havoc_{state.pc}")

    if op_symbol == "+":
        tuple_result = try_tuple_add_call(state, left, right)
        if tuple_result is not None:
            return tuple_result
        list_result = try_list_add_call(state, left, right)
        if list_result is not None:
            return list_result
    elif op_symbol == "+=":
        list_result = try_list_iadd_call(state, left, right)
        if list_result is not None:
            return list_result
    elif op_symbol == "*":
        tuple_result = try_tuple_mul_call(state, left, right)
        if tuple_result is not None:
            return tuple_result
        list_result = try_list_mul_call(state, left, right)
        if list_result is not None:
            return list_result
    elif op_symbol == "*=":
        list_result = try_list_imul_call(state, left, right)
        if list_result is not None:
            return list_result
    elif op_symbol in {"|", "|="}:
        dict_result = try_dict_merge_call(state, left, right, op_symbol)
        if dict_result is not None:
            return dict_result

    dunder_result = try_binary_dunder_call(state, ctx, left, right, op_symbol)
    if dunder_result is not None:
        return dunder_result

    none_type_error = binary_none_type_error(instr, state, ctx, left, right, base_op)
    if none_type_error is not None:
        return none_type_error

    string_type_error = binary_string_type_error(instr, state, ctx, left, right, base_op)
    if string_type_error is not None:
        return string_type_error

    if isinstance(left, SymbolicString) or isinstance(right, SymbolicString):
        return push_havoc_result(state, f"binop_{base_op}_{state.pc}")

    left_value = SymbolicValue.from_const(left)
    right_value = SymbolicValue.from_const(right)

    if base_op in {"+", "-", "*", "/", "//", "%"}:
        return handle_standard_numeric_op(instr, state, ctx, left_value, right_value, base_op)
    if base_op == "**":
        return handle_power_op(state, left_value, right_value)
    if base_op in {"<<", ">>"}:
        return handle_shift_op(state, left_value, right_value, base_op)
    return handle_bitwise_op(state, left_value, right_value, base_op)


def try_tuple_add_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply tuple concatenation for tuple-marked symbolic operands and tuple constants."""
    from pysymex.models.containers.tuples.helpers import get_symbolic_tuple
    from pysymex.models.containers.tuples.operations import TupleAddModel

    if not is_tuple_operand(left):
        return None
    if get_symbolic_tuple(left) is None or get_symbolic_tuple(right) is None:
        return None

    model_result = TupleAddModel().apply(
        [cast("StackValue", left), cast("StackValue", right)], {}, state
    )
    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def is_tuple_operand(value: object) -> bool:
    """Return whether *value* is definitely a tuple operand for sequence add."""
    if isinstance(value, tuple):
        return True
    return isinstance(value, SymbolicList) and getattr(value, "_type", None) == "tuple"


def try_tuple_mul_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply tuple repetition for definitely tuple-like operands and int counts."""
    from pysymex.models.containers.tuples.operations import TupleMulModel

    if is_tuple_operand(left) and is_list_repeat_count(right):
        args = [cast("StackValue", left), cast("StackValue", right)]
    elif is_tuple_operand(right) and is_list_repeat_count(left):
        args = [cast("StackValue", right), cast("StackValue", left)]
    else:
        return None

    model_result = TupleMulModel().apply(args, {}, state)
    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def try_list_add_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply the list concatenation model for heap-backed list operands."""
    from pysymex.models.containers.lists.operators import ListAddModel
    from pysymex.models.containers.lists.shared import get_symbolic_list

    if get_symbolic_list(left, state) is None or get_symbolic_list(right, state) is None:
        return None

    model_result = ListAddModel().apply(
        [cast("StackValue", left), cast("StackValue", right)], {}, state
    )
    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def try_list_mul_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply the list repetition model for heap-backed list/int operands."""
    from pysymex.models.containers.lists.operators import ListMulModel
    from pysymex.models.containers.lists.shared import get_symbolic_list

    if get_symbolic_list(left, state) is not None and is_list_repeat_count(right):
        args = [cast("StackValue", left), cast("StackValue", right)]
    elif get_symbolic_list(right, state) is not None and is_list_repeat_count(left):
        args = [cast("StackValue", right), cast("StackValue", left)]
    else:
        return None

    model_result = ListMulModel().apply(args, {}, state)
    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def try_list_iadd_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply in-place list concatenation for heap-backed list operands."""
    from pysymex.models.containers.lists.operators import ListIaddModel
    from pysymex.models.containers.lists.shared import get_symbolic_list

    if get_symbolic_list(left, state) is None:
        return None
    if get_symbolic_list(right, state) is None and not _list_iadd_operand_is_exact_iterable(
        right, state
    ):
        return None

    model_result = ListIaddModel().apply(
        [cast("StackValue", left), cast("StackValue", right)], {}, state
    )
    return _continue_list_inplace_result(state, left, model_result)


def _list_iadd_operand_is_exact_iterable(value: object, state: VMState) -> bool:
    from pysymex.models.builtins.core.helpers import resolve_heap_object
    from pysymex.models.builtins.core.iterator_items import concrete_iterable_items

    source = resolve_heap_object(cast("StackValue", value), state)
    return concrete_iterable_items(source, state) is not None


def try_list_imul_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply in-place list repetition for heap-backed list operands."""
    from pysymex.models.containers.lists.operators import ListImulModel
    from pysymex.models.containers.lists.shared import get_symbolic_list

    if get_symbolic_list(left, state) is None or not is_list_repeat_count(right):
        return None

    model_result = ListImulModel().apply(
        [cast("StackValue", left), cast("StackValue", right)], {}, state
    )
    return _continue_list_inplace_result(state, left, model_result)


def _continue_list_inplace_result(
    state: VMState,
    left: object,
    model_result: ModelResult,
) -> OpcodeResult:
    """Propagate list in-place model side effects and push the operator result."""
    from pysymex.execution.calls.helpers import as_mapping, as_stack_value
    from pysymex.execution.opcodes.common.functions.classes import (
        propagate_container_mutation_reference,
        propagate_list_mutation_reference,
    )

    mut = as_mapping(model_result.side_effects.get("list_mutation"))
    updated = None
    if mut is not None:
        original = mut.get("original_list")
        updated = mut.get("updated_list")
        if original is not None and updated is not None:
            state = propagate_list_mutation_reference(state, original, as_stack_value(updated))
    iterator_mut = as_mapping(model_result.side_effects.get("iterator_mutation"))
    if iterator_mut is not None:
        original_iterator = iterator_mut.get("original_iterator")
        updated_iterator = iterator_mut.get("updated_iterator")
        if original_iterator is not None and updated_iterator is not None:
            state = propagate_container_mutation_reference(
                state,
                original_iterator,
                as_stack_value(updated_iterator),
            )

    value = model_result.value
    if isinstance(left, SymbolicList) and updated is not None:
        value = updated
    state = state.push(as_stack_value(value))
    for constraint in model_result.constraints:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def try_dict_merge_call(
    state: VMState,
    left: object,
    right: object,
    op_symbol: str,
) -> OpcodeResult | None:
    """Apply dict merge operators before numeric bitwise fallback."""
    from pysymex.execution.opcodes.common.functions.classes import (
        propagate_container_mutation_reference,
    )
    from pysymex.execution.calls.helpers import as_mapping, as_stack_value
    from pysymex.models.containers.dicts.operators import (
        DictIorModel,
        DictOrModel,
        exact_dict_ior_items,
    )
    from pysymex.models.containers.dicts.shared import get_symbolic_dict

    if get_symbolic_dict(left, state) is None:
        return None
    if get_symbolic_dict(right, state) is None:
        if op_symbol != "|=" or exact_dict_ior_items(cast("StackValue", right), state) is None:
            return None

    model = DictIorModel() if op_symbol == "|=" else DictOrModel()
    model_result = model.apply([cast("StackValue", left), cast("StackValue", right)], {}, state)
    if op_symbol == "|=":
        mut = as_mapping(model_result.side_effects.get("dict_mutation"))
        if mut is not None:
            original = mut.get("original_dict")
            updated = mut.get("updated_dict")
            if original is not None and updated is not None:
                state = propagate_container_mutation_reference(
                    state, original, as_stack_value(updated)
                )
        iterator_mut = as_mapping(model_result.side_effects.get("iterator_mutation"))
        if iterator_mut is not None:
            original_iterator = iterator_mut.get("original_iterator")
            updated_iterator = iterator_mut.get("updated_iterator")
            if original_iterator is not None and updated_iterator is not None:
                state = propagate_container_mutation_reference(
                    state,
                    original_iterator,
                    as_stack_value(updated_iterator),
                )

    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def is_list_repeat_count(value: object) -> bool:
    """Return whether *value* can serve as a Python list repetition count."""
    if isinstance(value, (bool, int)):
        return True
    if isinstance(value, SymbolicValue):
        if isinstance(value.value, (bool, int)):
            return True
        return z3.is_true(z3.simplify(value.is_int))
    return False


def handle_unary_positive(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None = None,
) -> OpcodeResult:
    """Execute unary ``+`` (``UNARY_POSITIVE`` / intrinsic 5): pop and push ``+value``."""
    return _handle_unary_positive(instr, state, ctx)


def continue_unary_positive_value(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    value: object,
) -> OpcodeResult:
    """Apply unary ``+`` to a caller-supplied operand without an extra stack pop."""
    return _continue_unary_positive_value(instr, state, ctx, value)


def handle_unary_negative(state: VMState) -> OpcodeResult:
    """Execute Python-faithful unary negative semantics."""
    value = state.pop()
    if isinstance(value, (int, float, bool)):
        state = state.push(-value)
    else:
        symbolic = SymbolicValue.from_const(value)
        state = state.push(-symbolic)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_unary_not(state: VMState) -> OpcodeResult:
    """Execute Python-faithful unary ``not`` semantics."""
    value = state.pop()
    symbolic = SymbolicValue.from_const(value)
    state = state.push(symbolic.logical_not())
    return OpcodeResult.continue_with(state.advance_pc())


def handle_unary_invert(state: VMState) -> OpcodeResult:
    """Execute Python-faithful unary invert semantics."""
    value = state.pop()
    symbolic = SymbolicValue.from_const(value)
    result = symbolic.__invert__()
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


def handle_standard_numeric_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Delegate arithmetic to ``SymbolicValue`` for faithful typing semantics."""
    if op_symbol in {"/", "//", "%"}:
        zero_condition = z3.simplify(division_by_zero_condition(right))
        if z3.is_false(zero_condition):
            return continue_standard_numeric_op(state, left, right, op_symbol)
        constraints = state.path_constraints.to_list()
        zero_result = path_check_result([*constraints, zero_condition])
        if not zero_result.is_unsat:
            nonzero_condition = z3.Not(zero_condition)
            states: list[VMState] = []
            if zero_result.is_unknown or path_is_sat([*constraints, nonzero_condition]):
                success_state = state.fork().add_constraint(nonzero_condition)
                success_result = continue_standard_numeric_op(
                    success_state,
                    left,
                    right,
                    op_symbol,
                )
                states.extend(success_result.new_states)

            handler_state = jump_to_modeled_exception_handler(
                state.fork().add_constraint(zero_condition),
                ctx,
                instr,
                "ZeroDivisionError",
            )
            if handler_state is not None:
                states.append(handler_state)

            if states:
                return OpcodeResult.branch(states)
            return OpcodeResult.terminate()

    return continue_standard_numeric_op(state, left, right, op_symbol)


def continue_standard_numeric_op(
    state: VMState,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Push the result of ``+``, ``-``, ``*``, ``/``, ``//``, or ``%`` and advance PC."""
    try:
        if op_symbol == "+":
            result = left + right
        elif op_symbol == "-":
            result = left - right
        elif op_symbol == "*":
            result = left * right
        elif op_symbol == "/":
            result = left / right
        elif op_symbol == "//":
            result = left // right
        else:
            result = left % right
    except ZeroDivisionError:
        return OpcodeResult.terminate()
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


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
    if interval.contains_non_negative_small_range() and is_int_like(left):
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
            expr = left.z3_int * get_int_val(factor)
        else:
            expr = py_floor_div(left.z3_int, get_int_val(factor))
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
    if interval.contains_non_negative_small_range():
        assert interval.lower is not None
        assert interval.upper is not None
        if op_symbol == "<<":
            expr = piecewise_exact_shift_left(
                left.z3_int, right.z3_int, interval.lower, interval.upper
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
        bitvector = int_to_bv(value.z3_int)
    else:
        return value.z3_int % get_int_val(mask + 1)

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
                    z3.Int2BV(value.z3_int, width) & get_bitvec_val(mask, width),
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
