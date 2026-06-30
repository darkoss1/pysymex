from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.functions.call_ex import (
    handle_common_call_function_ex,
)
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability
from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True)
class Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def _instr(opname: str, arg: int = 0, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, arg=arg, argval=arg, offset=offset)


def _call_ex_target(
    *args: object, **kwargs: object
) -> tuple[tuple[object, ...], dict[str, object]]:
    return args, kwargs


def _call_function_ex(
    function: Callable[..., object],
    args_val: StackValue,
    kwargs_val: StackValue | None = None,
    dispatcher: OpcodeDispatcher | None = None,
) -> tuple[VMState, OpcodeDispatcher]:
    stack: list[StackValue] = [function, SymbolicNone("PUSH_NULL_None"), args_val]
    if kwargs_val is not None:
        stack.append(kwargs_val)
    state = VMState(stack=stack, pc=0)
    return state, dispatcher or OpcodeDispatcher()


def test_call_function_ex_reports_symbolic_int_star_args_type_error() -> None:
    args_val, type_constraint = SymbolicValue.symbolic_int("star_args")
    state, dispatcher = _call_function_ex(_call_ex_target, args_val)
    state = state.add_constraint(type_constraint)

    result = handle_common_call_function_ex(
        _instr("CALL_FUNCTION_EX", 0, offset=4), state, dispatcher
    )

    assert result.terminal is True
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "argument after * must be an iterable, not int" in result.issues[0].message


def test_call_function_ex_routes_symbolic_int_star_args_type_error() -> None:
    dispatcher = OpcodeDispatcher()
    call = _instr("CALL_FUNCTION_EX", 0, offset=4)
    dispatcher.set_instructions([call, _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    args_val, type_constraint = SymbolicValue.symbolic_int("star_args")
    state, _ = _call_function_ex(_call_ex_target, args_val, dispatcher=dispatcher)
    state = state.add_constraint(type_constraint)

    result = handle_common_call_function_ex(call, state, dispatcher)

    assert result.terminal is False
    assert result.issues == []
    routed = result.new_states[0].stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "TypeError"
    assert "argument after * must be an iterable, not int" in str(routed)


def test_call_function_ex_reports_symbolic_int_kwargs_type_error() -> None:
    kwargs_val, type_constraint = SymbolicValue.symbolic_int("kwargs")
    state, dispatcher = _call_function_ex(_call_ex_target, (), kwargs_val)
    state = state.add_constraint(type_constraint)

    result = handle_common_call_function_ex(
        _instr("CALL_FUNCTION_EX", 1, offset=4), state, dispatcher
    )

    assert result.terminal is True
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "argument after ** must be a mapping, not int" in result.issues[0].message


def test_call_function_ex_keeps_unknown_symbolic_star_args_unreported() -> None:
    args_val, type_constraint = SymbolicValue.symbolic("maybe_args")
    state, dispatcher = _call_function_ex(_call_ex_target, args_val)
    state = state.add_constraint(type_constraint)

    result = handle_common_call_function_ex(
        _instr("CALL_FUNCTION_EX", 0, offset=4), state, dispatcher
    )

    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 1
    assert PathSatisfiability.is_sat(list(result.new_states[0].path_constraints))
