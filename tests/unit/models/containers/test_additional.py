from __future__ import annotations

import inspect
from importlib import import_module
from types import ModuleType

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pysymex._internal.core.state.record import VMState
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.typing.protocols import StackValue

CONTAINER_MODEL_MODULES: tuple[ModuleType, ...] = tuple(
    import_module(name)
    for name in (
        "pysymex._internal.models.builtins.types.containers.lists.items",
        "pysymex._internal.models.builtins.types.containers.lists.mutations.growth",
        "pysymex._internal.models.builtins.types.containers.lists.mutations.ordering",
        "pysymex._internal.models.builtins.types.containers.lists.mutations.removal",
        "pysymex._internal.models.builtins.types.containers.lists.operators",
        "pysymex._internal.models.builtins.types.containers.lists.queries",
        "pysymex._internal.models.builtins.types.containers.dicts.access",
        "pysymex._internal.models.builtins.types.containers.dicts.constructors",
        "pysymex._internal.models.builtins.types.containers.dicts.mutations.bulk",
        "pysymex._internal.models.builtins.types.containers.dicts.mutations.items",
        "pysymex._internal.models.builtins.types.containers.dicts.mutations.pop",
        "pysymex._internal.models.builtins.types.containers.dicts.operators",
        "pysymex._internal.models.builtins.types.containers.dicts.views",
        "pysymex._internal.models.builtins.types.containers.bytes.bytearray.growth",
        "pysymex._internal.models.builtins.types.containers.bytes.bytearray.ordering",
        "pysymex._internal.models.builtins.types.containers.bytes.bytearray.removal",
        "pysymex._internal.models.builtins.types.containers.bytes.classification",
        "pysymex._internal.models.builtins.types.containers.bytes.decoding",
        "pysymex._internal.models.builtins.types.containers.bytes.formatting",
        "pysymex._internal.models.builtins.types.containers.bytes.search.affixes",
        "pysymex._internal.models.builtins.types.containers.bytes.search.counts",
        "pysymex._internal.models.builtins.types.containers.bytes.search.indexing",
        "pysymex._internal.models.builtins.types.containers.bytes.splitting",
        "pysymex._internal.models.builtins.types.containers.bytes.transforms.case",
        "pysymex._internal.models.builtins.types.containers.bytes.transforms.replace",
        "pysymex._internal.models.builtins.types.containers.bytes.transforms.trimming",
        "pysymex._internal.models.builtins.types.containers.bytes.translation",
        "pysymex._internal.models.builtins.types.containers.frozensets.operations",
        "pysymex._internal.models.builtins.types.containers.frozensets.queries",
        "pysymex._internal.models.builtins.types.containers.frozensets.relations",
        "pysymex._internal.models.builtins.types.containers.sets",
        "pysymex._internal.models.builtins.types.containers.strings",
        "pysymex._internal.models.builtins.types.containers.tuples",
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
