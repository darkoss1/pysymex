from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.frozensets.operations import (
    FrozensetCopyModel,
    FrozensetDiffModel,
    FrozensetIntersectionModel,
    FrozensetSymDiffModel,
    FrozensetUnionModel,
)
from pysymex._internal.models.builtins.types.containers.frozensets.queries import (
    FrozensetContainsModel,
    FrozensetHashModel,
)
from pysymex._internal.models.builtins.types.containers.frozensets.relations import (
    FrozensetDisjointModel,
    FrozensetIssubsetModel,
    FrozensetSupersetModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_frozenset_faithfulness_baseline() -> None:
    """Faithfulness baseline for immutable frozenset behavior."""
    values_cases: list[frozenset[int]] = [frozenset(), frozenset({1}), frozenset({1, 2})]
    for values in values_cases:
        assert values.union({9}) == frozenset(values).union({9})
        assert values.intersection({1, 9}) == frozenset(values).intersection({1, 9})


def test_frozenset_symbolic_error_paths() -> None:
    """Representative symbolic/error path checks."""
    FrozensetHashModel().apply([], {}, _state())
    FrozensetContainsModel().apply([], {}, _state())


def test_frozenset_edge_case_empty() -> None:
    """Edge case for empty frozenset."""
    empty: frozenset[int] = frozenset()
    assert len(empty) == 0


def test_frozenset_contains_symbolic_value_over_exact_items_preserves_membership() -> None:
    """frozenset.__contains__ should prove finite symbolic values are present."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = SymbolicList.from_const([0, 1])

    result = FrozensetContainsModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, z3.Not(result.value.z3_bool))
    assert solver.check() == z3.unsat


def test_frozenset_contains_symbolic_value_over_exact_items_keeps_missing_branch() -> None:
    """frozenset.__contains__ should keep false membership feasible when absent."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = SymbolicList.from_const([0])

    result = FrozensetContainsModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, z3.Not(result.value.z3_bool))
    assert solver.check() == z3.sat


EXACT_FROZENSET_METHODS: list[tuple[FunctionModel, list[StackValue]]] = [
    (FrozensetCopyModel(), []),
    (FrozensetSymDiffModel(), [SymbolicList.empty("other")]),
    (FrozensetIssubsetModel(), [SymbolicList.empty("other")]),
    (FrozensetSupersetModel(), [SymbolicList.empty("other")]),
    (FrozensetDisjointModel(), [SymbolicList.empty("other")]),
]


@pytest.mark.parametrize(("model", "method_args"), EXACT_FROZENSET_METHODS)
def test_exact_frozenset_methods_reject_invalid_calls(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    receiver = SymbolicList.empty("receiver")
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([receiver, *method_args, 1], {}),
        ([receiver, *method_args], {"unexpected": 1}),
    ]
    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"

    assert (
        "raised_exception" not in model.apply([receiver, *method_args], {}, _state()).side_effects
    )


@pytest.mark.parametrize(
    "model",
    [
        FrozensetSymDiffModel(),
        FrozensetIssubsetModel(),
        FrozensetSupersetModel(),
        FrozensetDisjointModel(),
    ],
)
def test_frozenset_operand_methods_reject_missing_operand(model: FunctionModel) -> None:
    effect = model.apply([SymbolicList.empty("receiver")], {}, _state()).side_effects.get(
        "raised_exception"
    )

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    "model", [FrozensetUnionModel(), FrozensetIntersectionModel(), FrozensetDiffModel()]
)
def test_variadic_frozenset_methods_allow_empty_and_multiple_operands(model: FunctionModel) -> None:
    receiver = SymbolicList.empty("receiver")
    valid_calls: list[list[StackValue]] = [
        [receiver],
        [receiver, SymbolicList.empty("left"), SymbolicList.empty("right")],
    ]
    for args in valid_calls:
        assert "raised_exception" not in model.apply(args, {}, _state()).side_effects

    effect = model.apply([receiver], {"unexpected": 1}, _state()).side_effects.get(
        "raised_exception"
    )
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
