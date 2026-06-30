from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.exceptions.policy import ModeledRuntimeException as ModeledException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.exceptions.matching import (
    handle_common_check_exc_match,
)
from pysymex._internal.execution.opcodes.common.exceptions.raising import handle_common_reraise


def _instr(
    opname: str,
    argval: object = None,
    offset: int = 0,
    arg: int | None = None,
) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, arg=arg, argval=argval, offset=offset)


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


def test_check_exc_match_refutes_unrelated_modeled_builtin_name() -> None:
    raised = ModeledException("TypeError", message="bad operand", raised_at=7)
    state = VMState(stack=[raised, ValueError], pc=0)

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


def test_reraise_reports_escaping_modeled_value_error() -> None:
    raised = SymbolicException.concrete(
        ValueError,
        "__len__() should return >= 0",
        raised_at=12,
    )
    state = VMState(stack=[raised], pc=0)

    result = handle_common_reraise(
        _instr("RERAISE", arg=1, argval=1, offset=20), state, OpcodeDispatcher()
    )

    assert result.terminal is True
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.kind is IssueKind.VALUE_ERROR
    assert "__len__() should return >= 0" in issue.message


def test_reraise_reports_retained_modeled_exception_below_lasti_marker() -> None:
    raised = SymbolicException.concrete(TypeError, "bad operand type for unary +", raised_at=7)
    state = VMState(stack=[None, raised, SymbolicValue.from_const(20)], pc=0)

    result = handle_common_reraise(
        _instr("RERAISE", arg=1, argval=1, offset=24),
        state,
        OpcodeDispatcher(),
    )

    assert result.terminal is True
    assert len(result.issues) == 1
    assert result.issues[0].kind is IssueKind.TYPE_ERROR
    assert result.issues[0].pc == 7


def test_reraise_reports_active_modeled_exception_when_cleanup_stack_has_no_exception() -> None:
    raised = SymbolicException.concrete(TypeError, "bad operand type for unary +")
    state = VMState(stack=[None], pc=0, active_exception=raised)

    result = handle_common_reraise(
        _instr("RERAISE", arg=0, argval=0, offset=24), state, OpcodeDispatcher()
    )

    assert result.terminal is True
    assert len(result.issues) == 1
    assert result.issues[0].kind is IssueKind.TYPE_ERROR


def test_reraise_routes_modeled_value_error_to_exception_table_without_issue() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("RERAISE", offset=4), _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([_Entry(4, 6, 20, 0, False)])
    raised = SymbolicException.concrete(
        ValueError,
        "__len__() should return >= 0",
        raised_at=12,
    )
    state = VMState(stack=[raised], pc=0)

    result = handle_common_reraise(_instr("RERAISE", arg=1, argval=1, offset=4), state, dispatcher)

    assert result.terminal is False
    assert result.issues == []
    assert result.new_states[0].pc == dispatcher.offset_to_index(20)
