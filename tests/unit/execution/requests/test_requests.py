from __future__ import annotations

from pysymex._internal.execution.requests.types import (
    CodeExecutionRequest,
    ExecutionRequest,
)


def _target(x: int) -> int:
    return x + 1


def test_function_execution_request_preserves_cache_token_for_none_symbolic_args() -> None:
    request = ExecutionRequest.from_inputs(_target, None, None)

    assert request.code is _target.__code__
    assert request.function_name == "_target"
    assert request.cache_symbolic_args_repr == "None"
    assert request.symbolic_arg_map() == {}
    assert request.initial_values is None


def test_function_execution_request_copies_mutable_inputs() -> None:
    symbolic_args = {"x": "int"}
    initial_values: dict[str, object] = {"x": 3}
    request = ExecutionRequest.from_inputs(_target, symbolic_args, initial_values)

    symbolic_args["x"] = "str"
    initial_values["x"] = 4

    assert request.symbolic_args == {"x": "int"}
    assert request.symbolic_arg_map() == {"x": "int"}
    assert request.initial_values == {"x": 3}
    assert request.cache_symbolic_args_repr == "{'x': 'int'}"


def test_code_execution_request_copies_mutable_inputs() -> None:
    code = compile("x = 1", "<request-test>", "exec")
    symbolic_vars = {"x": "int"}
    initial_globals: dict[str, object] = {"x": 1}

    request = CodeExecutionRequest.from_inputs(code, symbolic_vars, initial_globals)
    symbolic_vars["x"] = "str"
    initial_globals["x"] = 2

    assert request.code is code
    assert request.symbolic_vars == {"x": "int"}
    assert request.initial_globals == {"x": 1}
