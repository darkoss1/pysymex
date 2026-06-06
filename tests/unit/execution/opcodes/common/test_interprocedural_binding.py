from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass

from pysymex.analysis.detectors import IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.state.record import VMState
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.functions import handle_common_call
from pysymex.typing import StackValue


@dataclass(frozen=True)
class Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def _one_arg(a: object) -> object:
    return a


def _posonly(a: object, /) -> object:
    return a


def _type_error_message(
    function: Callable[..., object],
    *args: object,
    **kwargs: object,
) -> str:
    try:
        function(*args, **kwargs)
    except TypeError as exc:
        return str(exc)
    raise AssertionError("call did not raise TypeError")


def _instr(opname: str, arg: int = 0, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, arg=arg, argval=arg, offset=offset)


def _call(
    function: Callable[..., object],
    args: list[StackValue],
    kw_names: tuple[str, ...] = (),
    dispatcher: OpcodeDispatcher | None = None,
) -> OpcodeResult:
    stack: list[StackValue] = [SymbolicNone("PUSH_NULL_None"), function, *args]
    state = VMState(stack=stack, pc=0)
    state.pending_kw_names = kw_names or None
    ctx = dispatcher or OpcodeDispatcher()
    return handle_common_call(_instr("CALL", len(args), offset=4), state, ctx)


def test_cpython_rejects_user_function_binding_errors() -> None:
    assert "missing 1 required positional argument" in _type_error_message(_one_arg)
    assert _type_error_message(_one_arg, 1, 2) == (
        "_one_arg() takes 1 positional argument but 2 were given"
    )
    assert _type_error_message(_one_arg, b=1) == (
        "_one_arg() got an unexpected keyword argument 'b'"
    )
    assert _type_error_message(_one_arg, 1, a=2) == (
        "_one_arg() got multiple values for argument 'a'"
    )
    assert "positional-only arguments passed as keyword" in _type_error_message(_posonly, a=1)


def test_interprocedural_call_reports_extra_positional_type_error() -> None:
    result = _call(_one_arg, [1, 2])

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "takes 1 positional argument but 2 were given" in result.issues[0].message


def test_interprocedural_call_reports_unexpected_keyword_before_missing() -> None:
    result = _call(_one_arg, [1], ("b",))

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "unexpected keyword argument 'b'" in result.issues[0].message


def test_interprocedural_call_reports_duplicate_keyword_binding() -> None:
    result = _call(_one_arg, [1, 2], ("a",))

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "multiple values for argument 'a'" in result.issues[0].message


def test_interprocedural_call_reports_positional_only_keyword_binding() -> None:
    result = _call(_posonly, [1], ("a",))

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "positional-only arguments passed as keyword" in result.issues[0].message


def test_interprocedural_missing_argument_type_error_routes_to_handler() -> None:
    dispatcher = OpcodeDispatcher()
    call = _instr("CALL", 0, offset=4)
    dispatcher.set_instructions([call, _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    state = VMState(stack=[SymbolicNone("PUSH_NULL_None"), _one_arg], pc=0)

    result = handle_common_call(call, state, dispatcher)

    assert result.terminal is False
    assert result.issues == []
    routed = result.new_states[0].stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "TypeError"
    assert "missing required argument 'a'" in str(routed)
