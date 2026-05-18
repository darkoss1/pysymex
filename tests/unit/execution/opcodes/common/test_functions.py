from __future__ import annotations

import dis
from collections.abc import Iterator
from typing import cast

import pytest
import z3

from pysymex.analysis.detectors import IssueKind
from pysymex._typing import StackValue
from pysymex.core.objects.oop import EnhancedMethod
from pysymex.core.state import VMState, VMStateError
from pysymex.core.types import SymbolicNone, SymbolicObject, SymbolicValue
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.functions import (
    handle_common_call,
    handle_common_load_method,
)
from pysymex.sandbox.errors import SecurityViolationError


class ConcreteReceiver:
    safe_attr = 7

    def __call__(self) -> int:
        return self.safe_attr


def _yield_values(values: object) -> Iterator[object]:
    yield values


def _receiver_method(self: object, value: int) -> int:
    return value if self is not None else 0


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def test_handle_common_call_rejects_argument_stack_underflow() -> None:
    def identity(value: object) -> object:
        return value

    state = VMState(stack=[identity], pc=3)

    with pytest.raises(VMStateError, match="cannot satisfy 2 item"):
        handle_common_call(_instr("CALL", 1), state, OpcodeDispatcher())


def test_handle_common_call_rejects_null_callable_with_populated_receiver() -> None:
    state = VMState(stack=[None, 42], pc=4)

    with pytest.raises(VMStateError, match="callable slot is NULL"):
        handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())


def test_handle_common_call_terminates_uncaught_none_callable() -> None:
    state = VMState(stack=[None], pc=5)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []


def test_handle_common_call_terminates_symbolic_callable_forced_none() -> None:
    func, type_constraint = SymbolicValue.symbolic("maybe_func")
    state = VMState(stack=[func], pc=5).add_constraint(type_constraint).add_constraint(func.is_none)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []


def test_handle_common_call_reports_definite_non_callable_symbolic_int() -> None:
    func, type_constraint = SymbolicValue.symbolic_int("x")
    state = VMState(stack=[func], pc=5).add_constraint(type_constraint)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal
    assert len(result.issues) == 1
    assert result.issues[0].kind == IssueKind.TYPE_ERROR


def test_handle_common_call_consumes_direct_call_null_marker() -> None:
    state = VMState(stack=[SymbolicNone(), range, 3], pc=7)

    result = handle_common_call(_instr("CALL", 1), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert result.terminal is False
    assert len(next_state.stack) == 1
    assert not isinstance(next_state.stack[0], SymbolicNone)


def test_handle_common_call_returns_generator_without_entering_frame() -> None:
    iterator, iterator_constraint = SymbolicValue.symbolic("iterator")
    state = VMState(stack=[SymbolicNone(), all, _yield_values, iterator], pc=8)
    state = state.add_constraint(iterator_constraint)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    assert result.terminal is False
    assert next_state.pc == 9
    assert len(next_state.stack) == 3
    assert isinstance(next_state.stack[0], SymbolicNone)
    assert next_state.stack[1] is all
    assert next_state.call_stack == []
    assert not isinstance(next_state.stack[2], SymbolicNone)


def test_handle_common_load_method_allows_safe_concrete_attribute() -> None:
    state = VMState(stack=[ConcreteReceiver()], pc=5)

    result = handle_common_load_method(
        _instr("LOAD_METHOD", "safe_attr"), state, OpcodeDispatcher()
    )

    assert result.terminal is False
    assert result.new_states[0].stack[-1] == 7


def test_handle_common_load_method_blocks_dangerous_concrete_attribute() -> None:
    state = VMState(stack=[ConcreteReceiver()], pc=6)

    with pytest.raises(SecurityViolationError, match="__subclasses__"):
        handle_common_load_method(
            _instr("LOAD_METHOD", "__subclasses__"), state, OpcodeDispatcher()
        )


def test_handle_common_load_method_binds_heap_enhanced_method_to_receiver() -> None:
    receiver = SymbolicObject("self_obj", 101, z3.IntVal(101), {101})
    method = EnhancedMethod(func=_receiver_method, name="m")
    heap_object: dict[str, StackValue] = {"m": cast("StackValue", method)}
    state = VMState(stack=[receiver], pc=10).store_heap(receiver.address, heap_object)

    result = handle_common_load_method(_instr("LOAD_METHOD", "m"), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    loaded_method = next_state.stack[-2]
    explicit_receiver = next_state.stack[-1]
    assert isinstance(loaded_method, EnhancedMethod)
    assert loaded_method.bound_to is receiver
    assert explicit_receiver is receiver

    call_args, _ = loaded_method.get_call_args((explicit_receiver, 1), {})
    assert call_args == (receiver, 1)
