from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest
import z3

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.collections.build import (
    handle_common_build_list,
    handle_common_build_map,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.dicts import (
    handle_common_dict_merge_update,
)
from pysymex._internal.execution.opcodes.common.collections.subscript.delete import (
    handle_common_delete_subscr,
)
from pysymex._internal.execution.opcodes.common.collections.unpack.extended import (
    handle_common_unpack_ex,
)
from pysymex._internal.execution.opcodes.common.collections.unpack.sequence import (
    handle_common_unpack_sequence,
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


def test_handle_common_unpack_sequence_rejects_missing_source() -> None:
    state = VMState(pc=15)
    with pytest.raises(VMStateError, match="UNPACK_SEQUENCE"):
        handle_common_unpack_sequence(instr("UNPACK_SEQUENCE", 2), state, OpcodeDispatcher())


def test_handle_common_unpack_sequence_reports_known_too_few_values() -> None:
    build_state = VMState(stack=[1], pc=25)
    build_result = handle_common_build_list(
        instr("BUILD_LIST", 1, offset=0), build_state, OpcodeDispatcher()
    )
    state = build_result.new_states[0].set_pc(1)

    result = handle_common_unpack_sequence(
        instr("UNPACK_SEQUENCE", 2, offset=2), state, OpcodeDispatcher()
    )

    assert result.terminal is True
    assert result.issues[0].kind == IssueKind.VALUE_ERROR


def test_handle_common_unpack_sequence_uses_concrete_items_in_store_order() -> None:
    build_state = VMState(stack=[1, 2], pc=25)
    build_result = handle_common_build_list(
        instr("BUILD_LIST", 2, offset=0), build_state, OpcodeDispatcher()
    )
    state = build_result.new_states[0].set_pc(1)

    result = handle_common_unpack_sequence(
        instr("UNPACK_SEQUENCE", 2, offset=2), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    assert next_state.stack[-1] == 1
    assert next_state.stack[-2] == 2


def test_handle_common_unpack_sequence_uses_symbolic_tuple_payload_items() -> None:
    state = VMState(stack=[SymbolicValue.from_const((1, 2))], pc=26)

    result = handle_common_unpack_sequence(
        instr("UNPACK_SEQUENCE", 2, offset=2), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    assert next_state.stack[-1] == 1
    assert next_state.stack[-2] == 2


def test_handle_common_unpack_ex_uses_concrete_items_in_store_order() -> None:
    state = VMState(stack=[(1, 2, 3, 4)], pc=27)
    result = handle_common_unpack_ex(
        instr("UNPACK_EX", 0x0101, offset=2), state, OpcodeDispatcher()
    )
    next_state = result.new_states[0]
    assert next_state.stack[-1] == 1
    assert next_state.stack[-2] == [2, 3]
    assert next_state.stack[-3] == 4


def test_handle_common_unpack_ex_reports_known_too_few_values() -> None:
    state = VMState(stack=[(1,)], pc=28)
    result = handle_common_unpack_ex(
        instr("UNPACK_EX", 0x0101, offset=2), state, OpcodeDispatcher()
    )
    assert result.terminal is True
    assert result.issues[0].kind == IssueKind.VALUE_ERROR


def test_handle_common_unpack_ex_symbolic_star_target_is_list_with_length_relation() -> None:
    source, constraint = SymbolicList.symbolic("items")
    state = VMState(stack=[source], pc=29).add_constraint(constraint)
    result = handle_common_unpack_ex(
        instr("UNPACK_EX", 0x0101, offset=2), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    before = next_state.stack[-1]
    star = next_state.stack[-2]
    after = next_state.stack[-3]
    assert isinstance(before, SymbolicValue)
    assert isinstance(star, SymbolicList)
    assert isinstance(after, SymbolicValue)
    assert z3.is_true(simplify_expr(star.is_list))
    assert z3.is_true(simplify_expr(star.z3_len == source.z3_len - 2))
    assert z3.is_true(simplify_expr(before.z3_int == z3.Select(source.z3_array, z3.IntVal(0))))
    assert z3.is_true(simplify_expr(after.z3_int == z3.Select(source.z3_array, source.z3_len - 1)))


def test_handle_common_unpack_ex_generic_list_value_constrains_source_and_star_lengths() -> None:
    source_len = z3.Int("generic_len")
    source = SymbolicValue(
        _name="generic_list",
        z3_int=source_len,
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_list=z3.BoolVal(True),
        affinity_type="list",
    )
    state = VMState(stack=[source], pc=30)
    result = handle_common_unpack_ex(
        instr("UNPACK_EX", 0x0201, offset=2), state, OpcodeDispatcher()
    )

    next_state = result.new_states[0]
    star = next_state.stack[-2]
    assert isinstance(star, SymbolicList)
    solver = z3.Solver()
    solver.add(*next_state.path_constraints)
    solver.add(star.z3_len != source_len - 3)
    assert solver.check() == z3.unsat
    too_short = z3.Solver()
    too_short.add(*next_state.path_constraints, source_len == 2)
    assert too_short.check() == z3.unsat


def test_handle_common_delete_subscr_shrinks_heap_backed_symbolic_list() -> None:
    handle, _constraint = SymbolicObject.symbolic("list_obj", 41)
    state = VMState(stack=[handle, 1], memory={41: SymbolicList.from_const([1, 2, 3])}, pc=31)
    result = handle_common_delete_subscr(
        instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher()
    )
    updated = result.new_states[0].memory[41]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [1, 3]
    assert z3.is_true(simplify_expr(updated.z3_len == z3.IntVal(2)))


def test_handle_common_delete_subscr_mutates_concrete_list() -> None:
    items = [1, 2, 3]
    state = VMState(stack=cast("list[StackValue]", [items, -1]), pc=32)
    handle_common_delete_subscr(instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher())
    assert items == [1, 2]


def test_handle_common_delete_subscr_mutates_concrete_dict() -> None:
    mapping: dict[object, object] = {"a": 1, "b": 2}
    state = VMState(stack=cast("list[StackValue]", [mapping, "b"]), pc=33)

    result = handle_common_delete_subscr(
        instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher()
    )

    assert not result.terminal
    assert mapping == {"a": 1}
    assert result.new_states[0].stack == []


def test_handle_common_delete_subscr_reports_missing_concrete_key() -> None:
    state = VMState(stack=cast("list[StackValue]", [{"a": 1}, "missing"]), pc=34)

    result = handle_common_delete_subscr(
        instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher()
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.KEY_ERROR]
    assert "Possible KeyError: 'missing'" in result.issues[0].message


def test_handle_common_delete_subscr_reports_concrete_list_index_error() -> None:
    state = VMState(stack=cast("list[StackValue]", [[1], 3]), pc=35)

    result = handle_common_delete_subscr(
        instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher()
    )

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.INDEX_ERROR]
    assert "list assignment index out of range" in result.issues[0].message


def test_handle_common_delete_subscr_routes_key_error_to_handler() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("DELETE_SUBSCR", offset=4), instr("NOP", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    state = VMState(stack=cast("list[StackValue]", [{}, "missing"]), pc=36)

    result = handle_common_delete_subscr(instr("DELETE_SUBSCR", offset=4), state, dispatcher)

    assert not result.terminal
    assert result.issues == []
    next_state = result.new_states[0]
    assert next_state.pc == 1
    assert len(next_state.stack) == 1
    exception = next_state.stack[0]
    assert isinstance(exception, SymbolicException)
    assert exception.type_name == "KeyError"


def test_handle_common_delete_subscr_reports_string_deletion_type_error() -> None:
    state = VMState(stack=cast("list[StackValue]", [SymbolicString.from_const("abc"), 0]), pc=37)

    result = handle_common_delete_subscr(
        instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher()
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "'str' object doesn't support item deletion" in result.issues[0].message


def test_handle_common_delete_subscr_refreshes_direct_symbolic_list_alias() -> None:
    items = SymbolicList.from_const([1, 2, 3])
    state = VMState(stack=cast("list[StackValue]", [items, 1]), local_vars={"items": items}, pc=38)

    result = handle_common_delete_subscr(
        instr("DELETE_SUBSCR", offset=2), state, OpcodeDispatcher()
    )

    updated = result.new_states[0].local_vars["items"]
    assert isinstance(updated, SymbolicList)
    assert updated is not items
    assert updated.concrete_items == [1, 3]


def test_handle_common_dict_merge_update_rejects_missing_container() -> None:
    state = VMState(stack=[{"x": 1}], pc=16)
    with pytest.raises(VMStateError, match="DICT_UPDATE"):
        handle_common_dict_merge_update(instr("DICT_UPDATE", 1, arg=1), state, OpcodeDispatcher())


def _kwargs_target(**kwargs: object) -> dict[str, object]:
    return kwargs


def test_handle_common_dict_merge_reports_invalid_call_kwargs_mapping() -> None:
    stack = cast("list[StackValue]", [_kwargs_target, None, (), {}, 1])
    state = VMState(stack=stack, pc=39)

    result = handle_common_dict_merge_update(
        instr("DICT_MERGE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "argument after ** must be a mapping, not int" in result.issues[0].message


def test_handle_common_dict_merge_routes_non_string_keyword_key() -> None:
    dispatcher = OpcodeDispatcher()
    merge = instr("DICT_MERGE", 1, arg=1, offset=4)
    dispatcher.set_instructions([merge, instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    stack = cast("list[StackValue]", [_kwargs_target, None, (), {}, {1: 2}])
    state = VMState(stack=stack, pc=40)

    result = handle_common_dict_merge_update(merge, state, dispatcher)

    assert not result.terminal
    assert result.issues == []
    routed = result.new_states[0].stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "TypeError"
    assert "keywords must be strings" in str(routed)


def test_handle_common_dict_update_reports_invalid_mapping_operand() -> None:
    state = VMState(stack=[{}, 1], pc=41)

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "'int' object is not a mapping" in result.issues[0].message


def test_handle_common_dict_update_preserves_concrete_non_string_keys() -> None:
    build_result = handle_common_build_map(
        instr("BUILD_MAP", 0, arg=0, offset=2),
        VMState(pc=42),
        OpcodeDispatcher(),
    )
    state = build_result.new_states[0].push(cast("StackValue", {1: 2}))

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key(1) == (True, 2)
    assert updated.concrete_value_for_key("1") == (False, None)


def test_handle_common_dict_update_preserves_bool_and_string_keys() -> None:
    build_result = handle_common_build_map(
        instr("BUILD_MAP", 0, arg=0, offset=2),
        VMState(pc=43),
        OpcodeDispatcher(),
    )
    state = build_result.new_states[0].push(cast("StackValue", {True: 3, "1": 4}))

    result = handle_common_dict_merge_update(
        instr("DICT_UPDATE", 1, arg=1, offset=4),
        state,
        OpcodeDispatcher(),
    )

    updated = result.new_states[0].stack[-1]
    assert isinstance(updated, SymbolicDict)
    assert updated.concrete_value_for_key(True) == (True, 3)
    assert updated.concrete_value_for_key("1") == (True, 4)


def test_handle_common_unpack_sequence_marks_unknown_none_feasibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pysymex._internal.execution.opcodes.common.collections.unpack.sequence as sequence_ops
    from pysymex._internal.core.solver.engine.results import SolverResult

    container, constraint = SymbolicValue.symbolic("unpack_unknown_none")
    state = VMState(stack=[container], path_constraints=[constraint], pc=12)

    def unknown_check(*args: object, **kwargs: object) -> SolverResult:
        _ = args, kwargs
        return SolverResult.unknown()

    monkeypatch.setattr(sequence_ops, "_path_satisfiability_result", unknown_check)

    result = handle_common_unpack_sequence(
        instr("UNPACK_SEQUENCE", 1, offset=12), state, OpcodeDispatcher()
    )

    assert result.terminal is False
    assert result.degraded_passes == [sequence_ops.UNPACK_NONE_FEASIBILITY_UNKNOWN]
    assert result.fallback_events[0].label == sequence_ops.UNPACK_NONE_FEASIBILITY_UNKNOWN
