"""Concrete CPython differential contracts for pure builtin models."""

from __future__ import annotations

import builtins
import itertools
from collections.abc import Callable
from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.models.builtins.registry.models import ModelRegistry
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue

_EMPTY_LIST: list[object] = []
_ONE_LIST: list[object] = [1]
_EMPTY_DICT: dict[object, object] = {}
_EMPTY_SET: set[object] = set()
_EMPTY_FROZENSET: frozenset[object] = frozenset()

_VALUES: tuple[object, ...] = (
    None,
    False,
    0,
    1,
    -1,
    1.5,
    "",
    "a",
    b"",
    b"a",
    _EMPTY_LIST,
    _ONE_LIST,
    _EMPTY_DICT,
    (),
    (1,),
    _EMPTY_SET,
    _EMPTY_FROZENSET,
)

_UNARY_NAMES = (
    "abs",
    "bin",
    "oct",
    "hex",
    "chr",
    "ord",
    "hash",
    "len",
    "repr",
    "round",
    "bool",
    "int",
    "float",
    "str",
    "complex",
    "list",
    "tuple",
    "set",
    "frozenset",
    "dict",
    "bytes",
    "bytearray",
    "memoryview",
)

_BINARY_NAMES = ("divmod", "format", "pow")


def _cpython_outcome(target: Callable[..., object], args: tuple[object, ...]) -> str:
    """Return successful execution or the exact CPython exception class."""
    try:
        target(*args)
    except BaseException as exc:
        return type(exc).__name__
    return "accepted"


def _model_outcome(
    registry: ModelRegistry, target: Callable[..., object], args: tuple[object, ...]
) -> str:
    """Return successful model application or its modeled exception class."""
    model = registry.resolve_callable(target)
    assert model is not None
    stack_args = cast("list[StackValue]", list(args))
    result = model.apply(stack_args, {}, VMState())
    effect = result.side_effects.get("raised_exception")
    if SideEffects.is_raised_exception(effect):
        return effect["exception_type"]
    return "accepted"


def test_pure_builtin_concrete_exception_outcomes_match_cpython() -> None:
    """Concrete builtin models match CPython across the permanent small-value corpus."""
    registry = ModelRegistry()
    mismatches: list[str] = []
    cases = [
        *(itertools.product(_UNARY_NAMES, itertools.product(_VALUES, repeat=1))),
        *(itertools.product(_BINARY_NAMES, itertools.product(_VALUES, repeat=2))),
    ]

    for name, raw_args in cases:
        args = tuple(raw_args)
        target = cast("Callable[..., object]", getattr(builtins, name))
        expected = _cpython_outcome(target, args)
        actual = _model_outcome(registry, target, args)
        if actual != expected:
            mismatches.append(f"{name}{args!r}: CPython={expected}, model={actual}")

    assert mismatches == []
