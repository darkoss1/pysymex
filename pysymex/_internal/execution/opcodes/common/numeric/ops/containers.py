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

"""Container operator predispatch for Python ``BINARY_OP`` semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.models.contracts.results import ModelResult
    from pysymex._internal.typing.protocols import StackValue


def try_container_binary_op(
    state: VMState,
    left: object,
    right: object,
    op_symbol: str,
) -> OpcodeResult | None:
    """Try tuple/list/dict operator semantics before scalar numeric fallback."""
    if op_symbol == "+":
        tuple_result = _try_tuple_add_call(state, left, right)
        if tuple_result is not None:
            return tuple_result
        return _try_list_add_call(state, left, right)
    if op_symbol == "+=":
        return _try_list_iadd_call(state, left, right)
    if op_symbol == "*":
        tuple_result = _try_tuple_mul_call(state, left, right)
        if tuple_result is not None:
            return tuple_result
        return _try_list_mul_call(state, left, right)
    if op_symbol == "*=":
        return _try_list_imul_call(state, left, right)
    if op_symbol in {"|", "|="}:
        return _try_dict_merge_call(state, left, right, op_symbol)
    return None


def _try_tuple_add_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply tuple concatenation for tuple-marked symbolic operands and tuple constants."""
    from pysymex._internal.models.builtins.types.containers.tuples.operations import TupleAddModel
    from pysymex._internal.models.builtins.types.containers.tuples.tuple_ops import (
        TupleContainerOps,
    )

    if not _is_tuple_operand(left):
        return None
    if (
        TupleContainerOps.get_symbolic_tuple(left) is None
        or TupleContainerOps.get_symbolic_tuple(right) is None
    ):
        return None

    model_result = TupleAddModel().apply(
        [cast("StackValue", left), cast("StackValue", right)],
        {},
        state,
    )
    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def _is_tuple_operand(value: object) -> bool:
    """Return whether *value* is definitely a tuple operand for sequence add."""
    if isinstance(value, tuple):
        return True
    return isinstance(value, SymbolicList) and getattr(value, "_type", None) == "tuple"


def _try_tuple_mul_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply tuple repetition for definitely tuple-like operands and int counts."""
    from pysymex._internal.models.builtins.types.containers.tuples.operations import TupleMulModel

    if _is_tuple_operand(left) and _is_list_repeat_count(right):
        args = [cast("StackValue", left), cast("StackValue", right)]
    elif _is_tuple_operand(right) and _is_list_repeat_count(left):
        args = [cast("StackValue", right), cast("StackValue", left)]
    else:
        return None

    model_result = TupleMulModel().apply(args, {}, state)
    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def _try_list_add_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply the list concatenation model for heap-backed list operands."""
    from pysymex._internal.models.builtins.types.containers.lists.operators import ListAddModel

    if SymbolicList.resolve(left, state) is None or SymbolicList.resolve(right, state) is None:
        return None

    model_result = ListAddModel().apply(
        [cast("StackValue", left), cast("StackValue", right)],
        {},
        state,
    )
    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def _try_list_mul_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply the list repetition model for heap-backed list/int operands."""
    from pysymex._internal.models.builtins.types.containers.lists.operators import ListMulModel

    if SymbolicList.resolve(left, state) is not None and _is_list_repeat_count(right):
        args = [cast("StackValue", left), cast("StackValue", right)]
    elif SymbolicList.resolve(right, state) is not None and _is_list_repeat_count(left):
        args = [cast("StackValue", right), cast("StackValue", left)]
    else:
        return None

    model_result = ListMulModel().apply(args, {}, state)
    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def _try_list_iadd_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply in-place list concatenation for heap-backed list operands."""
    from pysymex._internal.models.builtins.types.containers.lists.operators import ListIaddModel

    if SymbolicList.resolve(left, state) is None:
        return None
    if SymbolicList.resolve(right, state) is None and not _list_iadd_operand_is_exact_iterable(
        right,
        state,
    ):
        return None

    model_result = ListIaddModel().apply(
        [cast("StackValue", left), cast("StackValue", right)],
        {},
        state,
    )
    return _continue_list_inplace_result(state, left, model_result)


def _list_iadd_operand_is_exact_iterable(value: object, state: VMState) -> bool:
    from pysymex._internal.models.builtins.iteration.sources import IterationSources

    source = SymbolicObject.resolve(cast("StackValue", value), state)
    return IterationSources.iterable_items(source, state) is not None


def _try_list_imul_call(state: VMState, left: object, right: object) -> OpcodeResult | None:
    """Apply in-place list repetition for heap-backed list operands."""
    from pysymex._internal.models.builtins.types.containers.lists.operators import ListImulModel

    if SymbolicList.resolve(left, state) is None or not _is_list_repeat_count(right):
        return None

    model_result = ListImulModel().apply(
        [cast("StackValue", left), cast("StackValue", right)],
        {},
        state,
    )
    return _continue_list_inplace_result(state, left, model_result)


def _continue_list_inplace_result(
    state: VMState,
    left: object,
    model_result: ModelResult,
) -> OpcodeResult:
    """Propagate list in-place model side effects and push the operator result."""
    from pysymex._internal.execution.calls.object.maps import as_mapping
    from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
        propagate_container_mutation_reference,
        propagate_list_mutation_reference,
    )

    mut = as_mapping(model_result.side_effects.get("list_mutation"))
    updated = None
    if mut is not None:
        original = mut.get("original_list")
        updated = mut.get("updated_list")
        if original is not None and updated is not None:
            state = propagate_list_mutation_reference(
                state,
                original,
                coerce_call_stack_value(updated),
            )
    iterator_mut = as_mapping(model_result.side_effects.get("iterator_mutation"))
    if iterator_mut is not None:
        original_iterator = iterator_mut.get("original_iterator")
        updated_iterator = iterator_mut.get("updated_iterator")
        if original_iterator is not None and updated_iterator is not None:
            state = propagate_container_mutation_reference(
                state,
                original_iterator,
                coerce_call_stack_value(updated_iterator),
            )

    value = model_result.value
    if isinstance(left, SymbolicList) and updated is not None:
        value = updated
    state = state.push(coerce_call_stack_value(value))
    for constraint in model_result.constraints:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def _try_dict_merge_call(
    state: VMState,
    left: object,
    right: object,
    op_symbol: str,
) -> OpcodeResult | None:
    """Apply dict merge operators before numeric bitwise fallback."""
    from pysymex._internal.execution.calls.object.maps import as_mapping
    from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.aliases import (
        propagate_container_mutation_reference,
    )
    from pysymex._internal.models.builtins.types.containers.dicts.operators import (
        DictIorModel,
        DictOrModel,
        exact_dict_ior_items,
    )
    from pysymex._internal.models.builtins.types.containers.dicts.shared import get_symbolic_dict

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
                    state,
                    original,
                    coerce_call_stack_value(updated),
                )
        iterator_mut = as_mapping(model_result.side_effects.get("iterator_mutation"))
        if iterator_mut is not None:
            original_iterator = iterator_mut.get("original_iterator")
            updated_iterator = iterator_mut.get("updated_iterator")
            if original_iterator is not None and updated_iterator is not None:
                state = propagate_container_mutation_reference(
                    state,
                    original_iterator,
                    coerce_call_stack_value(updated_iterator),
                )

    state = state.push(model_result.value)
    for constraint in model_result.constraints or []:
        state = state.add_constraint(cast("z3.BoolRef", constraint))
    return OpcodeResult.continue_with(state.advance_pc())


def _is_list_repeat_count(value: object) -> bool:
    """Return whether *value* can serve as a Python list repetition count."""
    if isinstance(value, (bool, int)):
        return True
    if isinstance(value, SymbolicValue):
        if isinstance(value.value, (bool, int)):
            return True
        return z3.is_true(simplify_expr(value.is_int))
    return False
