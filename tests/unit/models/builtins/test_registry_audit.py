"""Namespace-wide consistency and CPython binding audits for builtin models."""

from __future__ import annotations

import builtins

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.models.builtins.registry.defaults import default_builtin_models
from pysymex._internal.models.builtins.registry.models import ModelRegistry
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(global_vars={"__name__": "__main__"})


def _builtin_method_callable(qualname: str) -> object:
    empty_set: set[object] = set()
    callables: dict[str, object] = {
        "list.append": getattr([], "append"),
        "bytearray.append": getattr(bytearray(), "append"),
        "dict.copy": getattr({}, "copy"),
        "set.copy": getattr(empty_set, "copy"),
        "bytes.hex": getattr(b"", "hex"),
        "bytes.fromhex": getattr(bytes, "fromhex"),
        "bytes.maketrans": bytes.maketrans,
        "float.fromhex": getattr(float, "fromhex"),
        "str.format": getattr("", "format"),
    }
    return callables[qualname]


def _builtin_function_names() -> list[str]:
    names = [
        name
        for name in dir(builtins)
        if not name.startswith("_")
        and type(getattr(builtins, name)).__name__ == "builtin_function_or_method"
    ]
    names.append("__import__")
    return names


def test_every_public_cpython_builtin_callable_resolves() -> None:
    registry = ModelRegistry()
    missing = [
        name
        for name in dir(builtins)
        if not name.startswith("_")
        and callable(getattr(builtins, name))
        and registry.resolve_callable(getattr(builtins, name)) is None
    ]

    assert missing == []


def test_builtin_function_models_reject_impossible_excess_positional_binding() -> None:
    registry = ModelRegistry()
    variadic = {"breakpoint", "max", "min", "print"}
    failures: list[str] = []
    args: list[StackValue] = [1] * 20

    for name in _builtin_function_names():
        if name in variadic:
            continue
        model = registry.resolve_callable(getattr(builtins, name))
        assert model is not None
        result = model.apply(args, {}, _state())
        effect = result.side_effects.get("raised_exception")
        if not SideEffects.is_raised_exception(effect) or effect["exception_type"] != "TypeError":
            failures.append(name)

    assert failures == []


def test_builtin_function_models_reject_unknown_keywords() -> None:
    registry = ModelRegistry()
    failures: list[str] = []

    for name in _builtin_function_names():
        if name == "breakpoint":
            continue
        model = registry.resolve_callable(getattr(builtins, name))
        assert model is not None
        result = model.apply([], {"__pysymex_unexpected__": 1}, _state())
        effect = result.side_effects.get("raised_exception")
        if not SideEffects.is_raised_exception(effect) or effect["exception_type"] != "TypeError":
            failures.append(name)

    assert failures == []


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [([1] * 20, {}), ([], {"__pysymex_unexpected__": 1})],
)
def test_builtin_type_binding_matches_cpython_for_invalid_forms(
    args: list[StackValue], kwargs: dict[str, StackValue]
) -> None:
    registry = ModelRegistry()
    mismatches: list[str] = []

    for name in dir(builtins):
        if name.startswith("_"):
            continue
        constructor = getattr(builtins, name)
        if not isinstance(constructor, type):
            continue
        try:
            constructor(*args, **kwargs)
            expected = "accepted"
        except BaseException as exc:
            expected = type(exc).__name__

        model = registry.resolve_callable(constructor)
        assert model is not None
        result = model.apply(args, kwargs, _state())
        effect = result.side_effects.get("raised_exception")
        actual = effect["exception_type"] if SideEffects.is_raised_exception(effect) else "accepted"
        if actual != expected:
            mismatches.append(f"{name}: expected {expected}, modeled {actual}")

    assert mismatches == []


def test_builtin_exception_aliases_resolve_to_oserror_owner() -> None:
    registry = ModelRegistry()
    canonical = registry.resolve_callable(OSError)

    assert canonical is not None
    for alias_name in ("EnvironmentError", "IOError", "WindowsError"):
        if not hasattr(builtins, alias_name):
            continue
        alias = getattr(builtins, alias_name)
        assert alias is OSError
        assert registry.resolve_callable(alias) is canonical


def test_default_model_qualnames_have_unique_owners() -> None:
    models = default_builtin_models()
    qualnames = [model.qualname for model in models]

    assert all("." in qualname for qualname in qualnames)
    assert len(qualnames) == len(set(qualnames))


@pytest.mark.parametrize(
    "expected_key",
    [
        "list.append",
        "bytearray.append",
        "dict.copy",
        "set.copy",
        "bytes.hex",
        "bytes.fromhex",
        "bytes.maketrans",
        "float.fromhex",
        "str.format",
    ],
)
def test_builtin_method_callables_preserve_cpython_owner(expected_key: str) -> None:
    registry = ModelRegistry()

    model = registry.resolve_callable(_builtin_method_callable(expected_key))

    assert model is not None
    assert model.qualname == expected_key
