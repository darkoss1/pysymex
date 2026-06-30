"""Concrete builtin regressions found by CPython differential auditing."""

from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import UNBOUND
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.attributes.descriptors import DirModel
from pysymex._internal.models.builtins.bytes.constructors import BytearrayModel, BytesModel
from pysymex._internal.models.builtins.constructors.object import ObjectModel
from pysymex._internal.models.builtins.iteration.aggregates import SortedModel
from pysymex._internal.models.builtins.numeric.format import (
    BinModel,
    DivmodModel,
    HexModel,
    OctModel,
)
from pysymex._internal.models.builtins.numeric.max import MaxModel
from pysymex._internal.models.builtins.numeric.min import MinModel
from pysymex._internal.models.builtins.reflection.namespace import (
    DictModel,
    GlobalsModel,
    LocalsModel,
)
from pysymex._internal.models.builtins.text.codepoints import OrdModel, RoundModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def _assert_exception(result: object, exception_type: str) -> None:
    side_effects = getattr(result, "side_effects")
    effect = side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == exception_type


def test_scalar_models_reject_definite_none_inputs() -> None:
    results = [
        BinModel().apply([None], {}, _state()),
        OctModel().apply([None], {}, _state()),
        HexModel().apply([None], {}, _state()),
        OrdModel().apply([None], {}, _state()),
        RoundModel().apply([None], {}, _state()),
        DivmodModel().apply([None, 2], {}, _state()),
    ]

    for result in results:
        _assert_exception(result, "TypeError")


def test_ordering_builtins_report_incompatible_concrete_items() -> None:
    results = [
        MinModel().apply([1, "x"], {}, _state()),
        MaxModel().apply([1, "x"], {}, _state()),
        SortedModel().apply([[1, "x"]], {}, _state()),
    ]

    for result in results:
        _assert_exception(result, "TypeError")


def test_dict_constructor_reports_definite_malformed_pairs() -> None:
    malformed = DictModel().apply([[("key",)]], {}, _state())
    unhashable = DictModel().apply([[([], 1)]], {}, _state())

    _assert_exception(malformed, "ValueError")
    _assert_exception(unhashable, "TypeError")


def test_binary_constructors_report_out_of_range_exact_items() -> None:
    for model in (BytesModel(), BytearrayModel()):
        for invalid_items in ([-1], [256]):
            source: list[StackValue] = [*invalid_items]
            args: list[StackValue] = [source]
            _assert_exception(model.apply(args, {}, _state()), "ValueError")


def test_namespace_introspection_preserves_current_bound_values() -> None:
    state = VMState(local_vars={"local_value": 7}, global_vars={"global_value": 11})
    state = state.set_local("deleted", UNBOUND)

    directory = DirModel().apply([], {}, state)
    globals_result = GlobalsModel().apply([], {}, state)
    locals_result = LocalsModel().apply([], {}, state)

    assert isinstance(directory.value, SymbolicList)
    assert directory.value.concrete_items == ["local_value"]
    assert isinstance(globals_result.value, SymbolicDict)
    assert globals_result.value.concrete_value_for_key("global_value") == (True, 11)
    assert isinstance(locals_result.value, SymbolicDict)
    assert locals_result.value.concrete_value_for_key("local_value") == (True, 7)
    assert locals_result.value.concrete_value_for_key("deleted") == (False, None)


def test_object_constructor_returns_distinct_non_none_values() -> None:
    first = ObjectModel().apply([], {}, VMState(pc=1))
    second = ObjectModel().apply([], {}, VMState(pc=2))

    assert isinstance(first.value, SymbolicValue)
    assert isinstance(second.value, SymbolicValue)
    assert not z3.eq(first.value.z3_addr, second.value.z3_addr)
    assert z3.is_false(first.value.is_none)
    assert z3.is_false(second.value.is_none)
