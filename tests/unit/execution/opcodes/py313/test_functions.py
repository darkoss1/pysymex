from __future__ import annotations

import dis
import types
from typing import cast

import z3

from pysymex.typing import StackValue
from pysymex.analysis.detectors.detector.types import IssueKind
from pysymex.core.state.record import VMState
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.calls.model_dispatch import apply_model
from pysymex.execution.opcodes.py313 import functions
from pysymex.execution.calls.payload import function_payload


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


def test_handle_call_function_ex() -> None:
    """Test handle_call behavior with CALL_FUNCTION_EX."""
    state = VMState(stack=[SymbolicValue.from_const({}), SymbolicValue.from_const([])], pc=0)
    functions.handle_call(_instr("CALL_FUNCTION_EX", 0), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_call_kw() -> None:
    """Test handle_call behavior with CALL_KW."""
    state = VMState(stack=[SymbolicValue.from_const({}), SymbolicValue.from_const([])], pc=0)
    functions.handle_call(_instr("CALL_KW", 0), state, OpcodeDispatcher())
    assert state.pc == 1


def test_handle_make_function() -> None:
    """Test handle_make_function behavior."""
    state = VMState(stack=["code"], pc=0)
    functions.handle_make_function(_instr("MAKE_FUNCTION", 0), state, OpcodeDispatcher())
    assert isinstance(state.peek(), SymbolicValue)


def test_handle_load_build_class() -> None:
    """Test handle_load_build_class behavior."""
    state = VMState(pc=0)
    functions.handle_load_build_class(_instr("LOAD_BUILD_CLASS"), state, OpcodeDispatcher())
    top = state.peek()
    assert isinstance(top, SymbolicValue)
    assert top.name == "__build_class__"


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


def test_handle_load_super_attr() -> None:
    """Test handle_load_super_attr behavior."""
    state = VMState(stack=[1, 2, 3], pc=0)
    functions.handle_load_super_attr(_instr("LOAD_SUPER_ATTR", "x"), state, OpcodeDispatcher())


def test_handle_load_super_variants() -> None:
    """Test handle_load_super_variants behavior."""
    state = VMState(stack=[1, 2], pc=0)
    functions.handle_load_super_variants(
        _instr("LOAD_SUPER_METHOD", "m"), state, OpcodeDispatcher()
    )


def test_handle_set_function_attribute() -> None:
    """Test handle_set_function_attribute behavior."""
    state = VMState(stack=["attr", "func"], pc=0)
    functions.handle_set_function_attribute(
        _instr("SET_FUNCTION_ATTRIBUTE"), state, OpcodeDispatcher()
    )
    assert state.peek() == "func"


def test_handle_set_function_attribute_attaches_closure_to_symbolic_function() -> None:
    """Python 3.13 closure attributes should stay attached to the function object."""

    def outer() -> object:
        value = 0

        def inner() -> int:
            return value

        return inner

    inner_func = outer()
    assert isinstance(inner_func, types.FunctionType)
    inner_code = inner_func.__code__
    state = VMState(stack=[cast("StackValue", inner_code)], pc=0)
    functions.handle_make_function(_instr("MAKE_FUNCTION", 0), state, OpcodeDispatcher())
    func_obj = state.pop()
    cell = SymbolicObject("cell_value", 101, z3.IntVal(101), {101})
    state.stack.extend([(cell,), func_obj])

    functions.handle_set_function_attribute(
        _instr("SET_FUNCTION_ATTRIBUTE", 8), state, OpcodeDispatcher()
    )

    attached = state.peek()
    assert isinstance(attached, SymbolicValue)
    payload = function_payload(getattr(attached, "_modeled_object", None))
    assert payload is not None
    assert payload.closure == (cell,)


def test_handle_set_function_attribute_attaches_defaults_to_symbolic_function() -> None:
    def target(value: int = 1) -> int:
        return value

    state = VMState(stack=[cast("StackValue", target.__code__)], pc=0)
    functions.handle_make_function(_instr("MAKE_FUNCTION", 0), state, OpcodeDispatcher())
    func_obj = state.pop()
    state.stack.extend([cast("StackValue", (1,)), func_obj])

    functions.handle_set_function_attribute(
        _instr("SET_FUNCTION_ATTRIBUTE", 1), state, OpcodeDispatcher()
    )

    attached = state.peek()
    assert isinstance(attached, SymbolicValue)
    payload = function_payload(getattr(attached, "_modeled_object", None))
    assert payload is not None
    assert payload.defaults == (1,)


def test_handle_set_function_attribute_attaches_kwdefaults_to_symbolic_function() -> None:
    def target(*, value: int = 1) -> int:
        return value

    state = VMState(stack=[cast("StackValue", target.__code__)], pc=0)
    functions.handle_make_function(_instr("MAKE_FUNCTION", 0), state, OpcodeDispatcher())
    func_obj = state.pop()
    state.stack.extend([cast("StackValue", {"value": 1}), func_obj])

    functions.handle_set_function_attribute(
        _instr("SET_FUNCTION_ATTRIBUTE", 2), state, OpcodeDispatcher()
    )

    attached = state.peek()
    assert isinstance(attached, SymbolicValue)
    payload = function_payload(getattr(attached, "_modeled_object", None))
    assert payload is not None
    assert payload.kwdefaults == {"value": 1}


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
