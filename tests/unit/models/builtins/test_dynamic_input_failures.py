from __future__ import annotations

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.builtins.runtime.dynamic_io import (
    CompileModel,
    EvalModel,
    ExecModel,
    ImportModel,
    OpenModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    "model",
    [
        EvalModel(),
        ExecModel(),
    ],
)
def test_dynamic_execution_rejects_definite_non_code_source(model: FunctionModel) -> None:
    result = model.apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert "sink_event" not in result.side_effects


def test_compile_and_import_reject_definite_invalid_primary_arguments() -> None:
    compile_result = CompileModel().apply([1, "x", "exec"], {}, _state())
    import_result = ImportModel().apply([1], {}, _state())

    for result in (compile_result, import_result):
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_open_and_compile_reject_invalid_text_control_arguments() -> None:
    results = [
        OpenModel().apply(["x", 1], {}, _state()),
        CompileModel().apply(["1", 1, "eval"], {}, _state()),
        CompileModel().apply(["1", "x", 1], {}, _state()),
    ]

    for result in results:
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_compile_rejects_definite_invalid_mode_value_without_sink_evidence() -> None:
    result = CompileModel().apply(["1", "x", "bad"], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "ValueError"
    assert "sink_event" not in result.side_effects


def test_import_rejects_empty_name_and_invalid_relative_level() -> None:
    cases = [
        (ImportModel().apply([""], {}, _state()), "ValueError"),
        (
            ImportModel().apply(["sys"], {"level": -1}, _state()),
            "ValueError",
        ),
        (
            ImportModel().apply(["sys"], {"level": 1.0}, _state()),
            "TypeError",
        ),
    ]

    for result, exception_type in cases:
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == exception_type


def test_import_literal_os_returns_modeled_module_heap() -> None:
    state = _state()

    result = ImportModel().apply(["os"], {}, state)

    assert isinstance(result.value, SymbolicObject)
    assert result.value.name == "os"
    heap_value = state.load_heap(result.value.address)
    assert isinstance(heap_value, dict)
    assert heap_value["__module_name__"] == "os"
    assert "environ" in heap_value
    assert isinstance(heap_value["path"], SymbolicObject)


def test_import_literal_sys_uses_shared_module_registry() -> None:
    state = _state()

    result = ImportModel().apply(["sys"], {}, state)

    assert isinstance(result.value, SymbolicObject)
    heap_value = state.load_heap(result.value.address)
    assert isinstance(heap_value, dict)
    assert heap_value["__module_name__"] == "sys"
    assert "argv" in heap_value
