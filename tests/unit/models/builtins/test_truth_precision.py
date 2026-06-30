from __future__ import annotations

import types
from collections.abc import Sequence
from typing import cast

import pytest
import z3

from pysymex._internal.core.calls.payload import SymbolicFunctionPayload
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.truth import AllModel, AnyModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def _nonzero_genexpr_code() -> types.CodeType:
    def template(values: list[int]) -> object:
        return (value != 0 for value in values)

    for constant in template.__code__.co_consts:
        if isinstance(constant, types.CodeType):
            return constant
    raise AssertionError("missing generator expression code")


def _zero_genexpr_code() -> types.CodeType:
    def template(values: list[int]) -> object:
        return (value == 0 for value in values)

    for constant in template.__code__.co_consts:
        if isinstance(constant, types.CodeType):
            return constant
    raise AssertionError("missing generator expression code")


def _positive_genexpr_code() -> types.CodeType:
    def template(values: list[int]) -> object:
        return (value > 0 for value in values)

    for constant in template.__code__.co_consts:
        if isinstance(constant, types.CodeType):
            return constant
    raise AssertionError("missing generator expression code")


def _nonpositive_genexpr_code() -> types.CodeType:
    def template(values: list[int]) -> object:
        return (value <= 0 for value in values)

    for constant in template.__code__.co_consts:
        if isinstance(constant, types.CodeType):
            return constant
    raise AssertionError("missing generator expression code")


def _direct_truth_genexpr_code() -> types.CodeType:
    def template(values: list[int]) -> object:
        return (value for value in values)

    for constant in template.__code__.co_consts:
        if isinstance(constant, types.CodeType):
            return constant
    raise AssertionError("missing generator expression code")


def _modeled_generator_for_item(
    code: types.CodeType,
    item: SymbolicValue,
    name: str,
) -> ModeledGenerator:
    source = SymbolicList(
        name,
        z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort()),
        z3.IntVal(1),
        _concrete_items=[item],
    )
    iterator = SymbolicIterator(f"{name}_iter", source)
    return ModeledGenerator(
        "<genexpr>",
        SymbolicFunctionPayload(code=code),
        (iterator,),
        (),
    )


def _solver_status(constraints: Sequence[z3.BoolRef | z3.ExprRef]) -> z3.CheckSatResult:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check()


@pytest.mark.parametrize(
    ("model", "expected"),
    [(AllModel(), True), (AnyModel(), True)],
)
def test_truth_aggregators_decode_literal_symbolic_string(
    model: FunctionModel, expected: bool
) -> None:
    result = model.apply([SymbolicString.from_const("value")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is expected


@pytest.mark.parametrize("model", [AllModel(), AnyModel()])
def test_truth_aggregators_use_bool_affinity_for_opaque_generator(model: FunctionModel) -> None:
    """Opaque generators should not introduce multi-carrier symbolic fallbacks."""
    source, _constraint = SymbolicList.symbolic("generator_source")
    generator = SymbolicIterator("generator", source, is_generator=True)
    result = model.apply([generator], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.affinity_type == "bool"
    assert len(result.constraints) == 1


@pytest.mark.parametrize(
    ("model", "expected"),
    [(AllModel(), True), (AnyModel(), False)],
)
def test_truth_aggregators_resolve_empty_heap_list_handle(
    model: FunctionModel, expected: bool
) -> None:
    storage = SymbolicList.from_const([])
    handle = SymbolicObject("empty_list_handle", 10, z3.IntVal(10), {10})
    state = VMState(memory={10: storage})

    result = model.apply([handle], {}, state)

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is expected


@pytest.mark.parametrize("model", [AllModel(), AnyModel()])
def test_truth_aggregators_reject_concretely_typed_symbolic_non_iterable(
    model: FunctionModel,
) -> None:
    result = model.apply([SymbolicValue.from_const(1)], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_all_modeled_generator_nonzero_guard_rules_out_zero_item() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    generator = _modeled_generator_for_item(_nonzero_genexpr_code(), item, "all_values")

    result = AllModel().apply([cast(StackValue, generator)], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int == 0,
            ]
        )
        == z3.unsat
    )
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int == 1,
            ]
        )
        == z3.sat
    )


def test_any_modeled_generator_zero_guard_requires_a_zero_item() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    generator = _modeled_generator_for_item(_zero_genexpr_code(), item, "any_values")

    result = AnyModel().apply([cast(StackValue, generator)], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int != 0,
            ]
        )
        == z3.unsat
    )
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int == 0,
            ]
        )
        == z3.sat
    )


def test_all_modeled_generator_positive_guard_rules_out_nonpositive_item() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    generator = _modeled_generator_for_item(_positive_genexpr_code(), item, "positive_values")

    result = AllModel().apply([cast(StackValue, generator)], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int <= 0,
            ]
        )
        == z3.unsat
    )
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int == 1,
            ]
        )
        == z3.sat
    )


def test_any_modeled_generator_nonpositive_guard_allows_zero_item() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    generator = _modeled_generator_for_item(_nonpositive_genexpr_code(), item, "nonpositive_values")

    result = AnyModel().apply([cast(StackValue, generator)], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int > 0,
            ]
        )
        == z3.unsat
    )
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int == 0,
            ]
        )
        == z3.sat
    )


@pytest.mark.parametrize("model", [AllModel(), AnyModel()])
def test_truth_aggregator_direct_generator_truth_requires_truthy_item(
    model: FunctionModel,
) -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    generator = _modeled_generator_for_item(_direct_truth_genexpr_code(), item, "truth_values")

    result = model.apply([cast(StackValue, generator)], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int == 0,
            ]
        )
        == z3.unsat
    )
    assert (
        _solver_status(
            [
                item_constraint,
                *result.constraints,
                result.value.z3_bool,
                item.z3_int == 1,
            ]
        )
        == z3.sat
    )
