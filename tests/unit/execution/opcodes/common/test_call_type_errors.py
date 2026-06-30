from __future__ import annotations

import dis
import types
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.functions.call import handle_common_call
from pysymex._internal.execution.opcodes.common.functions.call_ex import (
    handle_common_call_function_ex,
)
from pysymex._internal.execution.opcodes.common.functions.setup import (
    handle_common_load_build_class,
    handle_common_make_function,
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


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


def _instr_with_arg(opname: str, arg: int, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, arg=arg, argval=arg, offset=offset)


def _compile_cpython_none_call() -> Callable[[], None]:
    namespace: dict[str, object] = {}
    exec(
        """
def none_call():
    none_obj = None
    return none_obj()
""",
        namespace,
    )
    function = namespace["none_call"]
    assert callable(function)
    return cast("Callable[[], None]", function)


def _call_ex_target(
    *args: object, **kwargs: object
) -> tuple[tuple[object, ...], dict[str, object]]:
    return args, kwargs


def _one_arg(value: object) -> object:
    return value


def _class_body_code(name: str) -> types.CodeType:
    module_code = compile(f"class {name}:\n    pass\n", "<call-layout-test>", "exec")
    for const in module_code.co_consts:
        if isinstance(const, types.CodeType) and const.co_name == name:
            return const
    raise AssertionError(f"missing class body code for {name}")


def _cpython_none_call_error(function: Callable[[], None]) -> str:
    try:
        function()
    except TypeError as exc:
        return str(exc)
    raise AssertionError("None call did not raise TypeError")


def _cpython_call_function_ex_error(statement: str) -> str:
    namespace: dict[str, object] = {"target": _call_ex_target}
    exec(
        f"""
def call_ex_case():
    {statement}
""",
        namespace,
    )
    function = namespace["call_ex_case"]
    assert callable(function)
    assert any(instr.opname == "CALL_FUNCTION_EX" for instr in dis.get_instructions(function))
    try:
        function()
    except TypeError as exc:
        return str(exc)
    raise AssertionError("CALL_FUNCTION_EX case did not raise TypeError")


def _call_function_ex(
    function: Callable[..., object],
    args_val: StackValue,
    kwargs_val: StackValue | None = None,
    dispatcher: OpcodeDispatcher | None = None,
) -> OpcodeResult:
    stack: list[StackValue] = [function, SymbolicNone("PUSH_NULL_None"), args_val]
    arg = 0
    if kwargs_val is not None:
        stack.append(kwargs_val)
        arg = 1
    state = VMState(stack=stack, pc=0)
    return handle_common_call_function_ex(
        _instr_with_arg("CALL_FUNCTION_EX", arg, offset=4),
        state,
        dispatcher or OpcodeDispatcher(),
    )


def test_cpython_none_call_raises_type_error() -> None:
    function = _compile_cpython_none_call()

    assert _cpython_none_call_error(function) == "'NoneType' object is not callable"
    assert any(instr.opname == "CALL" for instr in dis.get_instructions(function))


def test_cpython_call_function_ex_rejects_invalid_unpacking() -> None:
    assert "argument after * must be an iterable, not int" in _cpython_call_function_ex_error(
        "return target(*1)"
    )
    assert "argument after ** must be a mapping, not int" in _cpython_call_function_ex_error(
        "return target(**1)"
    )
    assert _cpython_call_function_ex_error("return target(**{1: 2})") == (
        "keywords must be strings"
    )


def test_handle_common_call_consumes_build_class_null_marker() -> None:
    state = VMState(stack=[SymbolicNone("PUSH_NULL_None")], pc=0)
    result = handle_common_load_build_class(
        _instr("LOAD_BUILD_CLASS", offset=2), state, OpcodeDispatcher()
    )
    state = result.new_states[0].push(_class_body_code("StackLayoutBox"))
    result = handle_common_make_function(_instr("MAKE_FUNCTION", 0), state, OpcodeDispatcher())
    state = result.new_states[0].push("StackLayoutBox")

    result = handle_common_call(_instr("CALL", 2, offset=12), state, OpcodeDispatcher())

    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 1
    next_state = result.new_states[0]
    assert len(next_state.stack) == 1
    class_value = next_state.stack[0]
    assert isinstance(class_value, SymbolicValue)
    assert class_value.name == "StackLayoutBox"
    assert class_value.affinity_type == "type"


def test_handle_common_call_reports_symbolic_none_callable() -> None:
    state = VMState(stack=[SymbolicNone("load_const_None"), SymbolicNone("PUSH_NULL_None")], pc=0)

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal is True
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert result.issues[0].message == "Possible TypeError: 'NoneType' object is not callable"


def test_handle_common_call_routes_none_callable_type_error_to_handler() -> None:
    dispatcher = OpcodeDispatcher()
    call = _instr("CALL", 0, offset=4)
    dispatcher.set_instructions([call, _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    state = VMState(stack=[SymbolicNone("load_const_None"), SymbolicNone("PUSH_NULL_None")], pc=0)

    result = handle_common_call(call, state, dispatcher)

    assert result.terminal is False
    assert result.issues == []
    next_state = result.new_states[0]
    assert next_state.pc == dispatcher.offset_to_index(20)
    routed = next_state.stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "TypeError"
    assert "'NoneType' object is not callable" in str(routed)


def test_handle_common_call_function_ex_reports_symbolic_none_callable() -> None:
    state = VMState(
        stack=[SymbolicNone("load_const_None"), SymbolicNone("PUSH_NULL_None"), ()],
        pc=0,
    )

    result = handle_common_call_function_ex(
        _instr_with_arg("CALL_FUNCTION_EX", 0), state, OpcodeDispatcher()
    )

    assert result.terminal is True
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]


def test_handle_common_call_function_ex_routes_none_callable_type_error_to_handler() -> None:
    dispatcher = OpcodeDispatcher()
    call = _instr_with_arg("CALL_FUNCTION_EX", 0, offset=4)
    dispatcher.set_instructions([call, _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    state = VMState(
        stack=[SymbolicNone("load_const_None"), SymbolicNone("PUSH_NULL_None"), ()],
        pc=0,
    )

    result = handle_common_call_function_ex(call, state, dispatcher)

    assert result.terminal is False
    routed = result.new_states[0].stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "TypeError"


def test_handle_common_call_prunes_unhandled_maybe_none_callable_to_normal_path() -> None:
    func, type_constraint = SymbolicValue.symbolic("maybe_func")
    state = VMState(stack=[func, SymbolicNone("PUSH_NULL_None")], pc=0).add_constraint(
        type_constraint
    )

    result = handle_common_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 1
    assert not PathSatisfiability.is_sat([*result.new_states[0].path_constraints, func.is_none])


def test_handle_common_call_routes_maybe_none_callable_to_handler_branch() -> None:
    dispatcher = OpcodeDispatcher()
    call = _instr("CALL", 0, offset=4)
    dispatcher.set_instructions([call, _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    func, type_constraint = SymbolicValue.symbolic("maybe_func")
    state = VMState(stack=[func, SymbolicNone("PUSH_NULL_None")], pc=0).add_constraint(
        type_constraint
    )

    result = handle_common_call(call, state, dispatcher)

    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 2
    routed = [
        item
        for state in result.new_states
        for item in state.stack
        if isinstance(item, SymbolicException)
    ]
    assert len(routed) == 1
    assert routed[0].type_name == "TypeError"


def test_handle_common_call_function_ex_reports_non_iterable_star_args() -> None:
    result = _call_function_ex(_call_ex_target, 1)

    assert result.terminal is True
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "argument after * must be an iterable, not int" in result.issues[0].message


def test_handle_common_call_function_ex_routes_non_iterable_star_args() -> None:
    dispatcher = OpcodeDispatcher()
    call = _instr_with_arg("CALL_FUNCTION_EX", 0, offset=4)
    dispatcher.set_instructions([call, _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])

    result = _call_function_ex(_call_ex_target, 1, dispatcher=dispatcher)

    assert result.terminal is False
    assert result.issues == []
    routed = result.new_states[0].stack[-1]
    assert isinstance(routed, SymbolicException)
    assert routed.type_name == "TypeError"
    assert "argument after * must be an iterable, not int" in str(routed)


def test_handle_common_call_function_ex_expands_concrete_dict_star_args() -> None:
    result = _call_function_ex(_one_arg, {"a": 1})

    assert result.terminal is False
    assert result.issues == []
    assert result.new_states[0].local_vars["value"] == "a"


def test_handle_common_call_function_ex_expands_concrete_symbolic_list_star_args() -> None:
    result = _call_function_ex(_one_arg, SymbolicList.from_const([3]))

    assert result.terminal is False
    assert result.issues == []
    assert result.new_states[0].local_vars["value"] == 3


def test_handle_common_call_function_ex_reports_invalid_kwargs_mapping() -> None:
    result = _call_function_ex(_call_ex_target, (), 1)

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "argument after ** must be a mapping, not int" in result.issues[0].message


def test_handle_common_call_function_ex_reports_non_string_keyword_key() -> None:
    result = _call_function_ex(_call_ex_target, (), cast("StackValue", {1: 2}))

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "keywords must be strings" in result.issues[0].message


def test_handle_common_call_function_ex_prunes_unhandled_maybe_none_callable() -> None:
    func, type_constraint = SymbolicValue.symbolic("maybe_func")
    state = VMState(stack=[func, SymbolicNone("PUSH_NULL_None"), ()], pc=0).add_constraint(
        type_constraint
    )

    result = handle_common_call_function_ex(
        _instr_with_arg("CALL_FUNCTION_EX", 0), state, OpcodeDispatcher()
    )

    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 1
    assert not PathSatisfiability.is_sat([*result.new_states[0].path_constraints, func.is_none])


def test_handle_common_call_function_ex_routes_maybe_none_callable_to_handler_branch() -> None:
    dispatcher = OpcodeDispatcher()
    call = _instr_with_arg("CALL_FUNCTION_EX", 0, offset=4)
    dispatcher.set_instructions([call, _instr("PUSH_EXC_INFO", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    func, type_constraint = SymbolicValue.symbolic("maybe_func")
    state = VMState(stack=[func, SymbolicNone("PUSH_NULL_None"), ()], pc=0).add_constraint(
        type_constraint
    )

    result = handle_common_call_function_ex(call, state, dispatcher)

    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 2
    routed = [
        item
        for state in result.new_states
        for item in state.stack
        if isinstance(item, SymbolicException)
    ]
    assert len(routed) == 1
    assert routed[0].type_name == "TypeError"
