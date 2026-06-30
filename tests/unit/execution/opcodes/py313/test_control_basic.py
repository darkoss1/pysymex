from __future__ import annotations

import dis
import sys
from typing import cast

import pytest
import z3

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.truthiness import get_truthy_expr
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.py311.control import (
    handle_for_iter,
    handle_get_iter,
    handle_get_len,
    handle_jump,
    handle_load_assertion_error,
    handle_no_op,
    handle_pop_jump_if_none,
    handle_pop_jump_if_not_none,
    handle_raise_varargs,
    handle_return_value,
)
from pysymex._internal.execution.opcodes.py312.control import (
    handle_call_intrinsic_1,
    handle_call_intrinsic_2,
    handle_end_for,
    handle_reserved,
    handle_return_const,
)
from pysymex._internal.execution.opcodes.py313.control.branches import handle_to_bool
from pysymex._internal.execution.opcodes.py313.control.lifecycle import (
    handle_enter_executor,
    handle_exit_init_check,
)
from pysymex._internal.typing.protocols import StackValue
from tests.unit.execution.opcodes.py313.control_helpers import instr


def test_handle_no_op() -> None:
    """Test handle_no_op behavior."""
    state = VMState(pc=2)
    handle_no_op(instr("NOP"), state, OpcodeDispatcher())
    assert state.pc == 3


def test_get_truthy_expr() -> None:
    """Test get_truthy_expr behavior."""
    assert z3.is_true(simplify_expr(get_truthy_expr(1)))
    assert z3.is_true(simplify_expr(z3.Not(get_truthy_expr(0))))


def test_handle_return_value() -> None:
    """Test handle_return_value behavior."""
    state = VMState(stack=[1], pc=0)
    result = handle_return_value(instr("RETURN_VALUE"), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_return_const() -> None:
    """Test handle_return_const behavior."""
    state = VMState(pc=0)
    result = handle_return_const(instr("RETURN_CONST", 5), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_jump() -> None:
    """Test handle_jump behavior with JUMP."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(pc=0)
    handle_jump(instr("JUMP", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_backward() -> None:
    """Test handle_jump behavior with JUMP_BACKWARD."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(pc=0)
    handle_jump(instr("JUMP_BACKWARD", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_backward_no_interrupt() -> None:
    """Test handle_jump behavior with JUMP_BACKWARD_NO_INTERRUPT."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(pc=0)
    handle_jump(instr("JUMP_BACKWARD_NO_INTERRUPT", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_jump_no_interrupt() -> None:
    """Test handle_jump behavior with JUMP_NO_INTERRUPT."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(pc=0)
    handle_jump(instr("JUMP_NO_INTERRUPT", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_resume() -> None:
    """Test handle_resume behavior (no-op, same as NOP)."""
    state = VMState(pc=0)
    handle_no_op(instr("RESUME"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_reserved() -> None:
    """RESERVED is internal bytecode and must not be treated as a no-op."""
    state = VMState(pc=0)
    with pytest.raises(RuntimeError, match="Unsupported internal opcode: RESERVED"):
        handle_reserved(instr("RESERVED"), state, OpcodeDispatcher())
    assert state.pc == 0


def test_handle_exit_init_check() -> None:
    """EXIT_INIT_CHECK is internal bytecode and must not be silently skipped."""
    state = VMState(stack=[SymbolicValue.from_const(1)], pc=0)
    with pytest.raises(RuntimeError, match="Unsupported internal opcode: EXIT_INIT_CHECK"):
        handle_exit_init_check(instr("EXIT_INIT_CHECK"), state, OpcodeDispatcher())
    assert state.pc == 0


def test_handle_pop_jump_if_none() -> None:
    """Test handle_pop_jump_if_none behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(stack=[SymbolicNone()], pc=0)
    handle_pop_jump_if_none(instr("POP_JUMP_IF_NONE", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_pop_jump_if_not_none() -> None:
    """Test handle_pop_jump_if_not_none behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    state = VMState(stack=[1], pc=0)
    handle_pop_jump_if_not_none(instr("POP_JUMP_IF_NOT_NONE", 10, offset=0), state, dispatcher)
    assert state.pc == 1


def test_handle_raise_varargs() -> None:
    """Test handle_raise_varargs behavior."""
    marker = SymbolicValue.from_const(0)
    marker = SymbolicValue(
        _name="NotImplementedError",
        z3_int=marker.z3_int,
        is_int=marker.is_int,
        z3_bool=marker.z3_bool,
        is_bool=marker.is_bool,
    )
    state = VMState(stack=[marker], pc=0)
    result = handle_raise_varargs(instr("RAISE_VARARGS", 1), state, OpcodeDispatcher())
    assert result.terminal is True


def test_handle_load_assertion_error() -> None:
    """Test handle_load_assertion_error behavior."""
    state = VMState(pc=0)
    handle_load_assertion_error(instr("LOAD_ASSERTION_ERROR"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_for_iter() -> None:
    """Test handle_for_iter behavior."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=4)])
    state = VMState(stack=[()], pc=0)
    result = handle_for_iter(instr("FOR_ITER", 4), state, dispatcher)
    assert len(result.new_states) == 1


def test_handle_get_iter() -> None:
    """Test handle_get_iter behavior."""
    state = VMState(stack=[[1, 2]], pc=0)
    handle_get_iter(instr("GET_ITER"), state, OpcodeDispatcher())
    assert len(state.stack) == 1


def test_handle_end_for() -> None:
    """Test handle_end_for behavior."""
    state = VMState(stack=[1, 2], pc=0)
    handle_end_for(instr("END_FOR"), state, OpcodeDispatcher())
    assert state.stack == [1]


def test_handle_end_for_pops_cleanup_sentinel_before_following_pop_top() -> None:
    """Python 3.13 ``END_FOR; POP_TOP`` should remove sentinel, then iterator."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("END_FOR"), instr("POP_TOP")])
    sentinel = SymbolicNone()
    state = VMState(stack=["with_exit", "iterator", sentinel], pc=0)

    handle_end_for(instr("END_FOR"), state, dispatcher)

    assert state.stack == ["with_exit", "iterator"]


def test_handle_to_bool() -> None:
    """Test handle_to_bool behavior."""
    state = VMState(stack=[1], pc=0)
    handle_to_bool(instr("TO_BOOL"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_get_len() -> None:
    """Test handle_get_len behavior."""
    state = VMState(stack=["abc"], pc=0)
    handle_get_len(instr("GET_LEN"), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_get_len_uses_concrete_list_length() -> None:
    """GET_LEN must not make concrete non-empty lists look empty."""
    state = VMState(stack=[[1, 2, 3]], pc=0)
    handle_get_len(instr("GET_LEN"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(simplify_expr(result.z3_int == z3.IntVal(3)))


@pytest.mark.parametrize(
    ("value", "expected_length"),
    [
        (SymbolicBytes.symbolic("data"), z3.Length(SymbolicBytes.symbolic("data").z3_bytes)),
        (SymbolicTuple.from_elements(1, 2), z3.IntVal(2)),
        (SymbolicSet.from_const({1, 2, 3}), z3.IntVal(3)),
    ],
)
def test_handle_get_len_uses_shared_symbolic_length_capability(
    value: object,
    expected_length: z3.ArithRef,
) -> None:
    state = VMState(stack=[cast("StackValue", value)], pc=0)

    handle_get_len(instr("GET_LEN"), state, OpcodeDispatcher())

    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(simplify_expr(result.z3_int == expected_length))


def test_handle_get_len_resolves_heap_backed_symbolic_list() -> None:
    """GET_LEN should use symbolic container length through object handles."""
    subject, _constraint = SymbolicObject.symbolic("list_obj", 11)
    storage = SymbolicList.empty("items")
    state = VMState(stack=[subject], memory={11: storage}, pc=0)
    handle_get_len(instr("GET_LEN"), state, OpcodeDispatcher())
    result = state.peek()
    assert isinstance(result, SymbolicValue)
    assert z3.is_true(simplify_expr(result.z3_int == storage.z3_len))


def test_handle_enter_executor() -> None:
    """ENTER_EXECUTOR is internal bytecode and must not be silently skipped."""
    state = VMState(pc=0)
    with pytest.raises(RuntimeError, match="Unsupported internal opcode: ENTER_EXECUTOR"):
        handle_enter_executor(instr("ENTER_EXECUTOR"), state, OpcodeDispatcher())
    assert state.pc == 0


def test_handle_call_intrinsic_1() -> None:
    """Test handle_call_intrinsic_1 behavior."""
    state = VMState(stack=[1], pc=0)
    handle_call_intrinsic_1(instr("CALL_INTRINSIC_1", 5), state, OpcodeDispatcher())
    assert state.peek() == 1


def test_handle_call_intrinsic_1_list_to_tuple_concrete_list() -> None:
    """LIST_TO_TUPLE consumes one list and pushes tuple-modeled items."""
    state = VMState(stack=[[1, 2]], pc=7)
    result = handle_call_intrinsic_1(instr("CALL_INTRINSIC_1", 6), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert len(next_state.stack) == 1
    tuple_value = next_state.peek()
    assert isinstance(tuple_value, SymbolicList)
    assert tuple_value.name == "tuple_7"
    assert tuple_value.concrete_items == [1, 2]
    assert z3.is_true(simplify_expr(tuple_value.z3_len == z3.IntVal(2)))


def test_handle_call_intrinsic_1_list_to_tuple_resolves_heap_backed_list() -> None:
    """LIST_TO_TUPLE must not lose concrete list payloads hidden behind handles."""
    handle, _constraint = SymbolicObject.symbolic("list_obj", 41)
    storage = SymbolicList.from_const([3, 4])
    state = VMState(stack=[handle], memory={41: storage}, pc=8)
    result = handle_call_intrinsic_1(instr("CALL_INTRINSIC_1", 6), state, OpcodeDispatcher())

    tuple_value = result.new_states[0].peek()
    assert isinstance(tuple_value, SymbolicList)
    assert tuple_value.name == "tuple_8"
    assert tuple_value.concrete_items == [3, 4]
    assert z3.is_true(simplify_expr(tuple_value.z3_len == z3.IntVal(2)))


def test_cpython_313_unary_positive_uses_call_intrinsic_1() -> None:
    """CPython 3.13 lowers unary plus to CALL_INTRINSIC_1."""
    if sys.version_info[:2] != (3, 13):
        return
    namespace: dict[str, object] = {}
    exec(compile("def f(x):\n    return +x\n", "<unary-positive>", "exec"), namespace)
    func = namespace["f"]
    assert callable(func)
    instructions = list(dis.get_instructions(func))
    assert any(item.opname == "CALL_INTRINSIC_1" and item.argval == 5 for item in instructions)


def test_cpython_313_starred_tuple_uses_list_to_tuple_intrinsic() -> None:
    """CPython 3.13 lowers starred tuple construction to LIST_TO_TUPLE intrinsic."""
    if sys.version_info[:2] != (3, 13):
        return
    namespace: dict[str, object] = {}
    exec(compile("def f(a):\n    return (*a,)\n", "<list-to-tuple>", "exec"), namespace)
    func = namespace["f"]
    assert callable(func)
    instructions = list(dis.get_instructions(func))
    assert any(item.opname == "CALL_INTRINSIC_1" and item.argval == 6 for item in instructions)


def test_handle_call_intrinsic_1_unary_positive_reports_string_type_error() -> None:
    """Python 3.13 unary-positive intrinsic must not pass through strings."""
    state = VMState(stack=["text"], pc=0)
    result = handle_call_intrinsic_1(instr("CALL_INTRINSIC_1", 5), state, OpcodeDispatcher())
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]


def test_handle_call_intrinsic_2() -> None:
    """Test handle_call_intrinsic_2 behavior."""
    state = VMState(stack=[1, 2], pc=0)
    handle_call_intrinsic_2(instr("CALL_INTRINSIC_2", 1), state, OpcodeDispatcher())
    assert state.peek() == 1


def test_handle_call_intrinsic_2_prep_reraise_star_ignores_none_remainder() -> None:
    """PREP_RERAISE_STAR keeps direct single-member cleanup when original is not a group."""
    reraised = SymbolicException.concrete(RuntimeError, "rerouted", raised_at=12)
    handle, _constraint = SymbolicObject.symbolic("reraised_list", 41)
    storage = SymbolicList.from_const([reraised, SymbolicNone()])
    state = VMState(stack=["old_exc", "original_group", handle], memory={41: storage}, pc=7)

    result = handle_call_intrinsic_2(
        instr("CALL_INTRINSIC_2", 1),
        state,
        OpcodeDispatcher(),
    )

    assert result.new_states[0].stack == ["old_exc", reraised]


def test_handle_call_intrinsic_2_prep_reraise_star_returns_single_retained_member() -> None:
    """A single retained handler-body exception is re-raised directly."""
    retained = SymbolicException.concrete(RuntimeError, "leftover", raised_at=12)
    original = SymbolicException.concrete(ExceptionGroup, "mixed", [retained], raised_at=4)
    handle, _constraint = SymbolicObject.symbolic("reraised_list", 41)
    storage = SymbolicList.from_const([retained, SymbolicNone()])
    state = VMState(stack=["old_exc", original, handle], memory={41: storage}, pc=7)

    result = handle_call_intrinsic_2(
        instr("CALL_INTRINSIC_2", 1),
        state,
        OpcodeDispatcher(),
    )

    assert result.new_states[0].stack == ["old_exc", retained]


def test_handle_call_intrinsic_2_prep_reraise_star_keeps_subgroup_remainder() -> None:
    """An unmatched except* subgroup is already group-shaped and must not be nested."""
    runtime_member = SymbolicException.concrete(RuntimeError, "leftover", raised_at=12)
    subgroup = SymbolicException.concrete(ExceptionGroup, "mixed", [runtime_member], raised_at=4)
    original = SymbolicException.concrete(
        ExceptionGroup,
        "mixed",
        [SymbolicException.concrete(ValueError, "handled", raised_at=4), runtime_member],
        raised_at=4,
    )
    handle, _constraint = SymbolicObject.symbolic("reraised_list", 41)
    storage = SymbolicList.from_const([subgroup])
    state = VMState(stack=["old_exc", original, handle], memory={41: storage}, pc=7)

    result = handle_call_intrinsic_2(
        instr("CALL_INTRINSIC_2", 1),
        state,
        OpcodeDispatcher(),
    )

    assert result.new_states[0].stack == ["old_exc", subgroup]


def test_handle_call_intrinsic_2_prep_reraise_star_returns_none_for_empty_remainder() -> None:
    """Normal except* handlers append None when no subgroup remains to re-raise."""
    retained = SymbolicException.concrete(RuntimeError, "leftover", raised_at=12)
    original = SymbolicException.concrete(ExceptionGroup, "mixed", [retained], raised_at=4)
    handle, _constraint = SymbolicObject.symbolic("reraised_list", 41)
    storage = SymbolicList.from_const([SymbolicNone()])
    state = VMState(stack=["old_exc", original, handle], memory={41: storage}, pc=7)

    result = handle_call_intrinsic_2(
        instr("CALL_INTRINSIC_2", 1),
        state,
        OpcodeDispatcher(),
    )

    assert result.new_states[0].stack[0] == "old_exc"
    assert isinstance(result.new_states[0].stack[1], SymbolicNone)
