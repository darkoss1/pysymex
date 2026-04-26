from __future__ import annotations

import inspect

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.containers import bytes as bytes_models
from pysymex.models.containers import dicts, frozensets, lists, sets, strings, tuples


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize("value", [b"", b"abc", b"A\tB", b"123"])
def test_bytes_parametrized_baseline(value: bytes) -> None:
    assert value.upper() == bytes(value).upper()
    assert value.lower() == bytes(value).lower()


@pytest.mark.parametrize("values", [frozenset(), frozenset({1}), frozenset({1, 2})])
def test_frozenset_parametrized_baseline(values: frozenset[int]) -> None:
    assert values.union({9}) == frozenset(values).union({9})


@given(st.lists(st.integers(), max_size=20), st.integers())
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_list_append_property(values: list[int], item: int) -> None:
    real_values = list(values)
    assert real_values.append(item) is None


def test_containers_auto_discovery_apply() -> None:
    modules = [lists, dicts, sets, tuples, strings, bytes_models, frozensets]
    for module in modules:
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                obj.__module__ == module.__name__
                and issubclass(obj, FunctionModel)
                and obj is not FunctionModel
            ):
                model = obj()
                args: list[StackValue] = []
                try:
                    result = model.apply(args, {}, _state())
                    assert isinstance(result, ModelResult)
                except NameError as exc:
                    assert "next_address" in str(exc)
