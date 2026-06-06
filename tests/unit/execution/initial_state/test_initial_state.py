"""Tests for execution initial-state input mapping."""

from __future__ import annotations

from pathlib import Path

from pysymex.execution.initial_state.builders import create_code_initial_state
from pysymex.execution.initial_state.hints import hint_to_type_str


def test_hint_to_type_str_uses_exact_type_identity() -> None:
    """Type names containing path should not become path-like hints."""

    class Empathic:
        pass

    assert hint_to_type_str(Path) == "path"
    assert hint_to_type_str(Empathic) == "int"
    assert hint_to_type_str(str | None) == "optional:str"
    assert hint_to_type_str(int | None) == "optional:int"


def test_create_code_initial_state_mirrors_module_symbolic_inputs_to_globals() -> None:
    code = compile("result = y\n", "<test>", "exec")

    state = create_code_initial_state(code, {"y": "int"})

    local_y = state.get_local("y")
    assert local_y is not None
    assert state.get_global("y") is local_y


def test_create_code_initial_state_seeds_builtin_names_for_code_execution() -> None:
    code = compile("raise RuntimeError('boom')\n", "<test>", "exec")

    state = create_code_initial_state(code)

    assert state.get_global("RuntimeError") is RuntimeError
    assert state.get_global("len") is len


def test_create_code_initial_state_initial_globals_override_builtin_names() -> None:
    code = compile("raise RuntimeError('boom')\n", "<test>", "exec")

    state = create_code_initial_state(code, initial_globals={"RuntimeError": ValueError})

    assert state.get_global("RuntimeError") is ValueError


def test_create_code_initial_state_keeps_function_symbolic_inputs_local_only() -> None:
    def target(x: int) -> int:
        return x

    state = create_code_initial_state(target.__code__, {"x": "int"})

    assert state.get_local("x") is not None
    assert state.get_global("x") is None
