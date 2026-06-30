from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest
import z3

from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.registry import class_registry
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.slices import materialize_concrete_slice
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.slices import (
    SliceBounds,
    build_slice_value,
    possible_zero_step_condition,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.collections.read.handler import (
    handle_common_binary_subscr,
)
from pysymex._internal.execution.opcodes.common.collections.subscript.delete import (
    handle_common_delete_subscr,
)
from pysymex._internal.execution.opcodes.common.collections.subscript.store import (
    handle_common_store_subscr,
)
from pysymex._internal.typing.protocols import StackValue
from tests.unit.execution.opcodes.common.collections_helpers import instr


@dataclass(frozen=True)
class Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def _modeled_index(_self: object) -> int:
    return 0


def _modeled_index_operand(name: str) -> SymbolicValue:
    modeled_cls = class_registry.register_class(SymbolicClass(name))
    modeled_cls.add_method("__index__", _modeled_index)
    instance = class_registry.instantiate(modeled_cls)
    value = SymbolicValue(
        _name=f"{name}_instance",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type=name,
    )
    value.attach_modeled_object(instance)
    return value


def test_store_subscr_normalizes_extended_slice_step_first() -> None:
    start = _modeled_index_operand("_StoreSliceStart")
    step = _modeled_index_operand("_StoreSliceStep")
    key, _constraint = build_slice_value(SliceBounds(start, 2, step), 30)
    state = VMState(stack=cast("list[StackValue]", [[9], [0, 1], key]), pc=30)

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    assert result.new_states[0].call_stack[-1].protocol_method == "__index_built_slice_step__"


def test_binary_subscr_normalizes_extended_slice_step_first() -> None:
    start = _modeled_index_operand("_ReadSliceStart")
    step = _modeled_index_operand("_ReadSliceStep")
    key, _constraint = build_slice_value(SliceBounds(start, 2, step), 31)
    state = VMState(stack=cast("list[StackValue]", [[0, 1], key]), pc=31)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.new_states[0].call_stack[-1].protocol_method == "__index_built_slice_step__"


def test_binary_subscr_reads_concrete_retained_slice() -> None:
    key, _constraint = build_slice_value(SliceBounds(0, 3, 2), 32)
    state = VMState(stack=cast("list[StackValue]", [[1, 2, 3], key]), pc=32)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.degraded_passes == []
    assert result.new_states[0].stack[-1] == [1, 3]


def test_materialize_concrete_slice_uses_symbolic_constant_payloads_without_z3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key, _constraint = build_slice_value(
        SliceBounds(
            SymbolicValue.from_const(None),
            SymbolicValue.from_const(3),
            SymbolicValue.from_const(2),
        ),
        32,
    )

    def fail_simplify(_expr: z3.ExprRef) -> z3.ExprRef:
        raise AssertionError("literal slice bounds should avoid Z3 simplification")

    monkeypatch.setattr(z3, "simplify", fail_simplify)

    assert materialize_concrete_slice(key) == slice(None, 3, 2)


def test_possible_zero_step_uses_symbolic_none_payload_without_z3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key, _constraint = build_slice_value(SliceBounds(0, 3, SymbolicValue.from_const(None)), 32)

    def fail_simplify(_expr: z3.ExprRef) -> z3.ExprRef:
        raise AssertionError("literal None step should avoid Z3 simplification")

    monkeypatch.setattr(z3, "simplify", fail_simplify)

    condition = possible_zero_step_condition(key)

    assert condition is not None
    assert z3.is_false(condition)


def test_binary_subscr_builds_heap_backed_retained_slice_result() -> None:
    key, _constraint = build_slice_value(SliceBounds(0, 3, 2), 33)
    source = SymbolicList.from_const([1, 2, 3])
    state = VMState(stack=cast("list[StackValue]", [source, key]), pc=33)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    handle = result.new_states[0].stack[-1]
    assert isinstance(handle, SymbolicObject)
    result_list = result.new_states[0].memory[handle.address]
    assert isinstance(result_list, SymbolicList)
    assert result_list.concrete_items == [1, 3]


def test_binary_subscr_reports_retained_zero_step() -> None:
    key, _constraint = build_slice_value(SliceBounds(0, 3, 0), 34)
    state = VMState(stack=cast("list[StackValue]", [[1, 2, 3], key]), pc=34)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert [issue.kind for issue in result.issues] == [IssueKind.VALUE_ERROR]
    assert "slice step cannot be zero" in result.issues[0].message


def test_binary_subscr_routes_retained_zero_step_to_exception_handler() -> None:
    key, _constraint = build_slice_value(SliceBounds(0, 3, 0), 35)
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("BINARY_SUBSCR", offset=4), instr("NOP", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    state = VMState(stack=cast("list[StackValue]", [[1, 2, 3], key]), pc=0)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR", offset=4), state, dispatcher)

    assert result.issues == []
    exception = result.new_states[0].stack[-1]
    assert isinstance(exception, SymbolicException)
    assert exception.type_name == "ValueError"


def test_store_subscr_reports_retained_zero_step() -> None:
    key, _constraint = build_slice_value(SliceBounds(0, 3, 0), 36)
    state = VMState(stack=cast("list[StackValue]", [[9], [1, 2, 3], key]), pc=36)

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    assert [issue.kind for issue in result.issues] == [IssueKind.VALUE_ERROR]
    assert "slice step cannot be zero" in result.issues[0].message


def test_delete_subscr_reports_retained_zero_step() -> None:
    key, _constraint = build_slice_value(SliceBounds(0, 3, 0), 37)
    state = VMState(stack=cast("list[StackValue]", [[1, 2, 3], key]), pc=37)

    result = handle_common_delete_subscr(instr("DELETE_SUBSCR"), state, OpcodeDispatcher())

    assert [issue.kind for issue in result.issues] == [IssueKind.VALUE_ERROR]
    assert "slice step cannot be zero" in result.issues[0].message


def test_store_subscr_mutates_heap_backed_concrete_retained_slice() -> None:
    container, _constraint = SymbolicObject.symbolic("items", 41)
    value, _constraint = SymbolicObject.symbolic("value", 42)
    key, _constraint = build_slice_value(SliceBounds(0, 4, 2), 38)
    state = VMState(
        stack=cast("list[StackValue]", [value, container, key]),
        memory={41: SymbolicList.from_const([0, 1, 0, 3]), 42: SymbolicList.from_const([1, 1])},
        pc=38,
    )

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    updated = result.new_states[0].memory[41]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [1, 1, 1, 3]
    assert result.degraded_passes == []


def test_store_subscr_reports_retained_extended_assignment_length_error() -> None:
    container, _constraint = SymbolicObject.symbolic("items", 43)
    value, _constraint = SymbolicObject.symbolic("value", 44)
    key, _constraint = build_slice_value(SliceBounds(0, 4, 2), 39)
    state = VMState(
        stack=cast("list[StackValue]", [value, container, key]),
        memory={43: SymbolicList.from_const([0, 1, 0, 3]), 44: SymbolicList.from_const([1])},
        pc=39,
    )

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    assert [issue.kind for issue in result.issues] == [IssueKind.VALUE_ERROR]
    assert (
        "attempt to assign sequence of size 1 to extended slice of size 2"
        in result.issues[0].message
    )


def test_delete_subscr_mutates_heap_backed_concrete_retained_slice() -> None:
    container, _constraint = SymbolicObject.symbolic("items", 45)
    key, _constraint = build_slice_value(SliceBounds(0, 4, 2), 40)
    state = VMState(
        stack=cast("list[StackValue]", [container, key]),
        memory={45: SymbolicList.from_const([0, 1, 0, 3])},
        pc=40,
    )

    result = handle_common_delete_subscr(instr("DELETE_SUBSCR"), state, OpcodeDispatcher())

    updated = result.new_states[0].memory[45]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [1, 3]
    assert result.degraded_passes == []


def test_delete_subscr_normalizes_extended_slice_step_first() -> None:
    start = _modeled_index_operand("_DeleteSliceStart")
    step = _modeled_index_operand("_DeleteSliceStep")
    key, _constraint = build_slice_value(SliceBounds(start, 2, step), 38)
    state = VMState(stack=cast("list[StackValue]", [[0, 1], key]), pc=38)

    result = handle_common_delete_subscr(instr("DELETE_SUBSCR"), state, OpcodeDispatcher())

    assert result.new_states[0].call_stack[-1].protocol_method == "__index_built_slice_step__"
