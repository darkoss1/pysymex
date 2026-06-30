from __future__ import annotations

import dis
from typing import cast

import z3

import pysymex._internal.execution.opcodes.py311.functions as functions
from pysymex._internal.core.calls.payload import function_payload
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.model.dispatch import apply_model
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.typing.protocols import StackValue


def _has_issue_kind(result: OpcodeResult | None, kind: IssueKind) -> bool:
    if result is None:
        return False
    return any(issue.kind == kind for issue in result.issues)


def _apply_model_for_test(
    state: VMState,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    raw: object = apply_model(state, func_obj, args, kwargs)
    assert raw is None or isinstance(raw, OpcodeResult)
    return raw


def _instr(opname: str, argval: object = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval)


def test_handle_precall() -> None:
    """Test handle_precall behavior."""
    state = VMState(pc=0)
    functions.handle_precall(_instr("PRECALL"), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_call() -> None:
    """Test handle_call behavior."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = functions.handle_call(_instr("CALL", 0), state, OpcodeDispatcher())
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]


def test_handle_load_method_reports_none_receiver() -> None:
    """LOAD_METHOD on None reports a feasible null dereference."""
    state = VMState(stack=[SymbolicNone()], pc=0)
    result = functions.handle_load_method(_instr("LOAD_METHOD", "x"), state, OpcodeDispatcher())
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.NULL_DEREFERENCE]


def test_handle_store_attr() -> None:
    """Test handle_store_attr behavior."""
    obj = SymbolicObject("o", -1, z3.IntVal(-1), {-1})
    state = VMState(stack=[123, obj], pc=0)
    result = functions.handle_store_attr(_instr("STORE_ATTR", "a"), state, OpcodeDispatcher())
    assert len(result.new_states) == 1
    assert result.new_states[0].pc == 1


def test_handle_delete_attr() -> None:
    """Test handle_delete_attr behavior."""
    state = VMState(stack=[1], pc=0)
    functions.handle_delete_attr(_instr("DELETE_ATTR", "a"), state, OpcodeDispatcher())
    assert state.stack == []


def test_handle_make_function() -> None:
    """Test handle_make_function behavior."""
    state = VMState(stack=["code"], pc=0)
    functions.handle_make_function(_instr("MAKE_FUNCTION", 0), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_make_function_preserves_defaults_and_kwdefaults() -> None:
    """MAKE_FUNCTION flags preserve CPython function default attributes."""

    def target(value: int = 1, *, enabled: bool = True) -> int:
        return value if enabled else 0

    state = VMState(
        stack=[
            cast("StackValue", (1,)),
            cast("StackValue", {"enabled": True}),
            cast("StackValue", target.__code__),
        ],
        pc=0,
    )
    functions.handle_make_function(_instr("MAKE_FUNCTION", 0x03), state, OpcodeDispatcher())

    attached = state.peek()
    assert isinstance(attached, SymbolicValue)
    payload = function_payload(getattr(attached, "_modeled_object", None))
    assert payload is not None
    assert payload.defaults == (1,)
    assert payload.kwdefaults == {"enabled": True}


def test_handle_load_build_class() -> None:
    """Test handle_load_build_class behavior."""
    state = VMState(pc=0)
    functions.handle_load_build_class(_instr("LOAD_BUILD_CLASS"), state, OpcodeDispatcher())
    top = state.peek()
    assert isinstance(top, SymbolicValue)
    assert top.name == "__build_class__"


def test_handle_kw_names() -> None:
    """Test handle_kw_names behavior."""
    state = VMState(pc=0)
    functions.handle_kw_names(_instr("KW_NAMES", ("x", "y")), state, OpcodeDispatcher())
    assert state.pending_kw_names == ("x", "y")


def test_handle_import_name() -> None:
    """Test handle_import_name behavior."""
    state = VMState(stack=[0, 0], pc=0)
    functions.handle_import_name(_instr("IMPORT_NAME", "math"), state, OpcodeDispatcher())
    top = state.peek()
    assert isinstance(top, SymbolicObject)
    assert top.name == "math"


def test_handle_import_from() -> None:
    """Test handle_import_from behavior."""
    state = VMState(stack=[1], pc=0)
    functions.handle_import_from(_instr("IMPORT_FROM", "sqrt"), state, OpcodeDispatcher())


def test_handle_import_star() -> None:
    """Test handle_import_star behavior."""
    state = VMState(stack=[1], pc=0)
    functions.handle_import_star(_instr("IMPORT_STAR"), state, OpcodeDispatcher())
    assert state.stack == []


def test_handle_call_function_ex() -> None:
    """Test handle_call_function_ex behavior."""
    state = VMState(stack=[SymbolicValue.from_const({}), SymbolicValue.from_const([])], pc=0)
    functions.handle_call_function_ex(_instr("CALL_FUNCTION_EX", 0), state, OpcodeDispatcher())
    assert state.pc == 1


def test_apply_model_converts_raised_exception_side_effect_to_attribute_error_issue() -> None:
    """getattr raised_exception side effect is surfaced as ATTRIBUTE_ERROR issue."""
    state = VMState(pc=0)
    result = _apply_model_for_test(state, "getattr", ["abc", "missing_attr"], {})
    assert _has_issue_kind(result, IssueKind.ATTRIBUTE_ERROR)


def test_apply_model_converts_critical_sink_event_to_runtime_error_issue() -> None:
    """eval sink_event side effect is surfaced as RUNTIME_ERROR issue."""
    state = VMState(pc=0)
    result = _apply_model_for_test(state, "eval", [SymbolicString.from_const("x + 1")], {})
    assert _has_issue_kind(result, IssueKind.RUNTIME_ERROR)
