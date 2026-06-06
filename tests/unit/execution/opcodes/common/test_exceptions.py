from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from pysymex.analysis.detectors import IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.exceptions import handle_common_check_exc_match


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


@dataclass(frozen=True)
class _Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


class _NotException:
    pass


def _cpython_catches_zero_division_as_arithmetic() -> str:
    try:
        raise ZeroDivisionError("z")
    except ArithmeticError:
        return "caught"
    except Exception:
        return "wrong"


def _compile_cpython_invalid_class_handler() -> Callable[[], None]:
    namespace: dict[str, object] = {"_NotException": _NotException}
    exec(
        """
def invalid_class_handler():
    try:
        raise ValueError("x")
    except _NotException:
        return
""",
        namespace,
    )
    function = namespace["invalid_class_handler"]
    assert callable(function)
    return cast("Callable[[], None]", function)


def _cpython_invalid_class_handler_error() -> tuple[str, str]:
    invalid_class_handler = _compile_cpython_invalid_class_handler()
    try:
        invalid_class_handler()
    except Exception as exc:
        return type(exc).__name__, str(exc)
    raise AssertionError("invalid exception handler did not raise")


def _peek_constant_bool(state: VMState) -> bool:
    top = state.peek()
    assert isinstance(top, SymbolicValue)
    value = top.value
    assert isinstance(value, bool)
    return value


def test_check_exc_match_uses_cpython_subclass_semantics() -> None:
    assert _cpython_catches_zero_division_as_arithmetic() == "caught"
    assert any(
        instr.opname == "CHECK_EXC_MATCH"
        for instr in dis.get_instructions(_cpython_catches_zero_division_as_arithmetic)
    )

    raised = SymbolicException.concrete(ZeroDivisionError)
    state = VMState(stack=[raised, ArithmeticError], pc=0)

    handle_common_check_exc_match(_instr("CHECK_EXC_MATCH"), state, OpcodeDispatcher())

    assert _peek_constant_bool(state) is True


def test_check_exc_match_reports_invalid_concrete_handler_class() -> None:
    exc_type, message = _cpython_invalid_class_handler_error()
    assert exc_type == "TypeError"
    assert "catching classes" in message
    invalid_class_handler = _compile_cpython_invalid_class_handler()
    assert any(
        instr.opname == "CHECK_EXC_MATCH" for instr in dis.get_instructions(invalid_class_handler)
    )

    raised = SymbolicException.concrete(ValueError)
    state = VMState(stack=[raised, _NotException], pc=0)

    result = handle_common_check_exc_match(_instr("CHECK_EXC_MATCH"), state, OpcodeDispatcher())

    assert result.terminal is True
    assert result.issues[0].kind is IssueKind.TYPE_ERROR
    assert "catching classes" in result.issues[0].message


def test_check_exc_match_invalid_tuple_entry_takes_precedence_over_match() -> None:
    raised = SymbolicException.concrete(ValueError)
    state = VMState(stack=[raised, (ValueError, 1)], pc=0)

    result = handle_common_check_exc_match(_instr("CHECK_EXC_MATCH"), state, OpcodeDispatcher())

    assert result.terminal is True
    assert result.issues[0].kind is IssueKind.TYPE_ERROR


def test_check_exc_match_refutes_unrelated_concrete_handler() -> None:
    raised = SymbolicException.concrete(ZeroDivisionError)
    state = VMState(stack=[raised, LookupError], pc=0)

    handle_common_check_exc_match(_instr("CHECK_EXC_MATCH"), state, OpcodeDispatcher())

    assert _peek_constant_bool(state) is False


def test_check_exc_match_flattens_concrete_handler_tuple() -> None:
    raised = SymbolicException.concrete(ZeroDivisionError)
    state = VMState(stack=[raised, (LookupError, ArithmeticError)], pc=0)

    handle_common_check_exc_match(_instr("CHECK_EXC_MATCH"), state, OpcodeDispatcher())

    assert _peek_constant_bool(state) is True


def test_check_exc_match_routes_invalid_handler_type_error_to_exception_table() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions(
        [_instr("CHECK_EXC_MATCH", offset=4), _instr("PUSH_EXC_INFO", offset=20)]
    )
    dispatcher.set_exception_entries([_Entry(4, 6, 20, 0, False)])
    state = VMState(stack=[SymbolicException.concrete(ValueError), 1], pc=0)

    result = handle_common_check_exc_match(_instr("CHECK_EXC_MATCH", offset=4), state, dispatcher)

    assert result.terminal is False
    next_state = result.new_states[0]
    assert next_state.pc == dispatcher.offset_to_index(20)
    routed = next_state.stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "TypeError"
    assert "catching classes" in str(routed)
