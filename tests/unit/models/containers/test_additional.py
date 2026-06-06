from __future__ import annotations

import inspect
from importlib import import_module
from types import ModuleType

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from pysymex.typing import StackValue
from pysymex.core.state.record import VMState
from pysymex.models.builtins.base import FunctionModel, ModelResult

CONTAINER_MODEL_MODULES: tuple[ModuleType, ...] = tuple(
    import_module(name)
    for name in (
        "pysymex.models.containers.lists.items",
        "pysymex.models.containers.lists.mutations.growth",
        "pysymex.models.containers.lists.mutations.ordering",
        "pysymex.models.containers.lists.mutations.removal",
        "pysymex.models.containers.lists.operators",
        "pysymex.models.containers.lists.queries",
        "pysymex.models.containers.dicts.access",
        "pysymex.models.containers.dicts.constructors",
        "pysymex.models.containers.dicts.mutations.bulk",
        "pysymex.models.containers.dicts.mutations.items",
        "pysymex.models.containers.dicts.mutations.pop",
        "pysymex.models.containers.dicts.operators",
        "pysymex.models.containers.dicts.views",
        "pysymex.models.containers.bytes.bytearray.growth",
        "pysymex.models.containers.bytes.bytearray.misc",
        "pysymex.models.containers.bytes.bytearray.removal",
        "pysymex.models.containers.bytes.classification",
        "pysymex.models.containers.bytes.decoding",
        "pysymex.models.containers.bytes.formatting",
        "pysymex.models.containers.bytes.search.affixes",
        "pysymex.models.containers.bytes.search.counts",
        "pysymex.models.containers.bytes.search.indexing",
        "pysymex.models.containers.bytes.splitting",
        "pysymex.models.containers.bytes.transforms.case",
        "pysymex.models.containers.bytes.transforms.replace",
        "pysymex.models.containers.bytes.transforms.trimming",
        "pysymex.models.containers.bytes.translation",
        "pysymex.models.containers.frozensets.operations",
        "pysymex.models.containers.frozensets.queries",
        "pysymex.models.containers.frozensets.relations",
        "pysymex.models.containers.sets",
        "pysymex.models.containers.strings",
        "pysymex.models.containers.tuples",
    )
)


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize("value", [b"", b"abc", b"A\tB", b"123"])
def test_bytes_parametrized_baseline(value: bytes) -> None:
    assert value.upper() == bytes(value).upper()
    assert value.lower() == bytes(value).lower()


@pytest.mark.parametrize("values", [frozenset[int](), frozenset({1}), frozenset({1, 2})])
def test_frozenset_parametrized_baseline(values: frozenset[int]) -> None:
    assert values.union({9}) == frozenset(values).union({9})


@given(st.lists(st.integers(), max_size=20), st.integers())
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_list_append_property(values: list[int], item: int) -> None:
    real_values = list(values)
    assert real_values.append(item) is None


def test_containers_auto_discovery_apply() -> None:
    for module in CONTAINER_MODEL_MODULES:
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
