from __future__ import annotations

import pytest

import pysymex.models.builtins as builtins_models
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    "model",
    [
        builtins_models.EvalModel(),
        builtins_models.ExecModel(),
    ],
)
def test_dynamic_execution_rejects_definite_non_code_source(model: FunctionModel) -> None:
    result = model.apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
    assert "sink_event" not in result.side_effects


def test_compile_and_import_reject_definite_invalid_primary_arguments() -> None:
    compile_result = builtins_models.CompileModel().apply([1, "x", "exec"], {}, _state())
    import_result = builtins_models.ImportModel().apply([1], {}, _state())

    for result in (compile_result, import_result):
        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_open_and_compile_reject_invalid_text_control_arguments() -> None:
    results = [
        builtins_models.OpenModel().apply(["x", 1], {}, _state()),
        builtins_models.CompileModel().apply(["1", 1, "eval"], {}, _state()),
        builtins_models.CompileModel().apply(["1", "x", 1], {}, _state()),
    ]

    for result in results:
        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_compile_rejects_definite_invalid_mode_value_without_sink_evidence() -> None:
    result = builtins_models.CompileModel().apply(["1", "x", "bad"], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "ValueError"
    assert "sink_event" not in result.side_effects


def test_import_rejects_empty_name_and_invalid_relative_level() -> None:
    cases = [
        (builtins_models.ImportModel().apply([""], {}, _state()), "ValueError"),
        (
            builtins_models.ImportModel().apply(["sys"], {"level": -1}, _state()),
            "ValueError",
        ),
        (
            builtins_models.ImportModel().apply(["sys"], {"level": 1.0}, _state()),
            "TypeError",
        ),
    ]

    for result, exception_type in cases:
        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == exception_type


def test_import_literal_os_returns_modeled_module_heap() -> None:
    state = _state()

    result = builtins_models.ImportModel().apply(["os"], {}, state)

    assert isinstance(result.value, SymbolicObject)
    assert result.value.name == "os"
    heap_value = state.load_heap(result.value.address)
    assert isinstance(heap_value, dict)
    assert heap_value["__module_name__"] == "os"
    assert "environ" in heap_value
    assert isinstance(heap_value["path"], SymbolicObject)
