from __future__ import annotations

import dataclasses
import sys

import pytest

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.fallback import FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.opcodes.common.control_fallbacks import (
    UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL,
    UNSUPPORTED_GENERATOR,
)
from pysymex.execution.opcodes.py313 import exceptions
from pysymex.models.objects import SymbolicClass, class_registry
from pysymex.models.builtins.exceptions import ExceptionTypeModel
from tests.unit.execution.opcodes.py313.exception_helpers import instr

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="Requires Python 3.13+",
)


def test_handle_setup_finally() -> None:
    """Test handle_setup_finally behavior."""
    state = VMState(pc=0)
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=10)])
    exceptions.handle_setup_finally(instr("SETUP_FINALLY", 10, offset=0), state, dispatcher)
    assert len(state.block_stack) == 1


def test_handle_pop_block() -> None:
    """Test handle_pop_block behavior."""
    state = VMState(pc=0)
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=8)])
    exceptions.handle_setup_finally(instr("SETUP_FINALLY", 8, offset=0), state, dispatcher)
    exceptions.handle_pop_block(instr("POP_BLOCK"), state, dispatcher)
    assert len(state.block_stack) == 0


def test_handle_push_exc_info() -> None:
    """Test handle_push_exc_info behavior."""
    state = VMState(stack=["exc"], pc=0)
    exceptions.handle_push_exc_info(instr("PUSH_EXC_INFO"), state, OpcodeDispatcher())
    assert len(state.stack) == 2


def test_handle_setup_with_has_cpython_stack_delta() -> None:
    state = VMState(stack=["manager"], pc=0)

    result = exceptions.handle_setup_with(instr("SETUP_WITH", 10), state, OpcodeDispatcher())

    assert result.new_states == [state]
    assert result.terminal is False
    assert state.pc == 1
    assert len(state.stack) == 2
    assert len(state.path_constraints) == 2


def test_handle_pop_except() -> None:
    """Test handle_pop_except behavior."""
    state = VMState(stack=["e"], pc=0)
    exceptions.handle_pop_except(instr("POP_EXCEPT"), state, OpcodeDispatcher())
    assert state.stack == []


def test_handle_check_exc_match() -> None:
    """Test handle_check_exc_match behavior."""
    base = SymbolicValue.from_const(1)
    exc = SymbolicValue(
        _name="ValueError",
        z3_int=base.z3_int,
        is_int=base.is_int,
        z3_bool=base.z3_bool,
        is_bool=base.is_bool,
    )
    state = VMState(stack=[exc, ValueError], pc=0)
    exceptions.handle_check_exc_match(instr("CHECK_EXC_MATCH"), state, OpcodeDispatcher())
    top = state.peek()
    assert isinstance(top, SymbolicValue)


def test_handle_cleanup_throw() -> None:
    """Test handle_cleanup_throw behavior."""
    state = VMState(pc=2)
    exceptions.handle_cleanup_throw(instr("CLEANUP_THROW"), state, OpcodeDispatcher())
    assert state.pc == 3


def test_handle_reraise() -> None:
    """Test handle_reraise behavior."""
    state = VMState(stack=["exc"], pc=0)
    result = exceptions.handle_reraise(instr("RERAISE", 0), state, OpcodeDispatcher())
    assert result.terminal is True
    assert len(result.issues) == 0


def test_handle_with_except_start() -> None:
    """Test handle_with_except_start behavior."""
    state = VMState(pc=0)
    exceptions.handle_with_except_start(instr("WITH_EXCEPT_START"), state, OpcodeDispatcher())


def test_handle_before_with() -> None:
    """Test handle_before_with behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_before_with(instr("BEFORE_WITH"), state, OpcodeDispatcher())


def test_handle_before_with_records_unsupported_context_manager_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_IncompleteContextManager"))
    modeled_cls.add_method("__enter__")
    modeled_obj = class_registry.instantiate(modeled_cls)
    manager = SymbolicValue.symbolic("instance_IncompleteContextManager")[0]
    manager.attach_modeled_object(modeled_obj)
    state = VMState(stack=[manager], pc=8)

    result = exceptions.handle_before_with(instr("BEFORE_WITH"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.degraded_passes == [UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_CONTEXT_MANAGER_PROTOCOL
    assert event.owner == "execution.opcodes.control"
    assert event.reason == "modeled context manager is missing __enter__ or __exit__"
    assert event.pc == 8
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.HIGH
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_before_async_with() -> None:
    """Test handle_before_async_with behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_before_async_with(instr("BEFORE_ASYNC_WITH"), state, OpcodeDispatcher())


def test_handle_end_async_for() -> None:
    """Test handle_end_async_for behavior."""
    state = VMState(stack=[1, 2], pc=0)
    exceptions.handle_end_async_for(instr("END_ASYNC_FOR"), state, OpcodeDispatcher())
    assert state.stack == []


def test_handle_get_aiter() -> None:
    """Test handle_get_aiter behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_get_aiter(instr("GET_AITER"), state, OpcodeDispatcher())


def test_handle_get_anext() -> None:
    """Test handle_get_anext behavior."""
    state = VMState(pc=0)
    exceptions.handle_get_anext(instr("GET_ANEXT"), state, OpcodeDispatcher())


def test_handle_get_awaitable() -> None:
    """Test handle_get_awaitable behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_get_awaitable(instr("GET_AWAITABLE"), state, OpcodeDispatcher())


def test_handle_send() -> None:
    """Test handle_send behavior."""
    state = VMState(stack=[1, 2], pc=0)
    exceptions.handle_send(instr("SEND"), state, OpcodeDispatcher())


def test_handle_yield_value() -> None:
    """Test handle_yield_value behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_yield_value(instr("YIELD_VALUE"), state, OpcodeDispatcher())


def test_handle_end_send() -> None:
    """Test handle_end_send behavior."""
    state = VMState(stack=[1, 2], pc=0)
    exceptions.handle_end_send(instr("END_SEND"), state, OpcodeDispatcher())
    assert len(state.stack) == 1


def test_handle_get_yield_from_iter() -> None:
    """Test handle_get_yield_from_iter behavior."""
    state = VMState(stack=[1], pc=0)
    exceptions.handle_get_yield_from_iter(instr("GET_YIELD_FROM_ITER"), state, OpcodeDispatcher())


def test_handle_check_eg_match() -> None:
    """Test handle_check_eg_match behavior."""
    state = VMState(stack=[1, 2], pc=0)
    exceptions.handle_check_eg_match(instr("CHECK_EG_MATCH"), state, OpcodeDispatcher())


def test_handle_check_eg_match_resolves_fully_known_matching_group() -> None:
    inner = ExceptionTypeModel(ZeroDivisionError).apply(["zero"], {}, VMState()).value
    members = dataclasses.replace(SymbolicList.empty("members"), _concrete_items=[inner])
    handle, _constraint = SymbolicObject.symbolic("members_handle", 101)
    group = ExceptionTypeModel(ExceptionGroup).apply(["group", handle], {}, VMState()).value
    state = VMState(stack=[group, ZeroDivisionError], memory={101: members}, pc=0)

    exceptions.handle_check_eg_match(instr("CHECK_EG_MATCH"), state, OpcodeDispatcher())

    assert isinstance(state.stack[-2], SymbolicNone)
    assert state.stack[-1] is group


def test_handle_check_eg_match_resolves_fully_known_unmatched_group() -> None:
    inner = ExceptionTypeModel(ValueError).apply(["bad"], {}, VMState()).value
    group = ExceptionTypeModel(ExceptionGroup).apply(["group", [inner]], {}, VMState()).value
    state = VMState(stack=[group, TypeError], pc=0)

    exceptions.handle_check_eg_match(instr("CHECK_EG_MATCH"), state, OpcodeDispatcher())

    assert state.stack[-2] is group
    assert isinstance(state.stack[-1], SymbolicNone)


def test_handle_setup_cleanup() -> None:
    """Test handle_setup_cleanup behavior."""
    state = VMState(pc=0)
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("NOP", offset=0), instr("NOP", offset=4)])
    exceptions.handle_setup_cleanup(instr("SETUP_CLEANUP", 4, offset=0), state, dispatcher)
    assert len(state.block_stack) == 1


def test_handle_interpreter_exit() -> None:
    """Test handle_interpreter_exit behavior."""
    result = exceptions.handle_interpreter_exit(
        instr("INTERPRETER_EXIT"), VMState(), OpcodeDispatcher()
    )
    assert result.terminal is True


def test_handle_raise_varargs() -> None:
    """Test handle_raise_varargs behavior."""
    state = VMState(stack=[SymbolicValue.from_const(1)], pc=0)
    result = exceptions.handle_raise_varargs(
        instr("RAISE_VARARGS", 1, offset=0), state, OpcodeDispatcher()
    )
    assert result.terminal is True
    assert len(result.issues) == 0


def test_handle_return_generator() -> None:
    """Test handle_return_generator behavior."""
    state = VMState(pc=0)
    result = exceptions.handle_return_generator(
        instr("RETURN_GENERATOR"), state, OpcodeDispatcher()
    )
    assert result is not None
    assert result.degraded_passes == [UNSUPPORTED_GENERATOR]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == UNSUPPORTED_GENERATOR
    assert event.owner == "execution.opcodes.control"
    assert event.reason == "RETURN_GENERATOR created an abstract generator object"
    assert event.pc == 0
    assert event.soundness is SoundnessTag.PRECISION_LOSS
    assert event.false_positive_risk is RiskLevel.LOW
    assert event.false_negative_risk is RiskLevel.HIGH
