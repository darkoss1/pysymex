from __future__ import annotations

from typing import cast

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.lists.items import (
    ListCopyModel,
    ListDelitemModel,
    ListGetitemModel,
    ListSetitemModel,
)
from pysymex._internal.models.builtins.types.containers.lists.mutations.growth import (
    ListAppendModel,
    ListExtendModel,
    ListInsertModel,
)
from pysymex._internal.models.builtins.types.containers.lists.mutations.ordering import (
    ListReverseModel,
    ListSortModel,
)
from pysymex._internal.models.builtins.types.containers.lists.mutations.removal import (
    ListClearModel,
    ListPopModel,
    ListRemoveModel,
)
from pysymex._internal.models.builtins.types.containers.lists.operators import (
    ListAddModel,
    ListMulModel,
)
from pysymex._internal.models.builtins.types.containers.lists.queries import (
    ListContainsModel,
    ListCountModel,
    ListIndexModel,
)
from pysymex._internal.core.types.containers.sequence_precision import (
    slice_concrete_backed_sequence,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_append_model_faithfulness() -> None:
    """Faithfulness: list.append returns None like Python."""
    values = [1, 2]
    item = 3
    real_values = list(values)
    real_result = real_values.append(item)
    args: list[StackValue] = [list(values), item]
    model_result = ListAppendModel().apply(args, {}, _state())
    assert real_result is None
    assert isinstance(model_result.value, SymbolicNone)


def test_mutating_models_concrete_none_result() -> None:
    """Concrete path: mutating list methods return None-like symbolic value."""
    seq: list[StackValue] = [1, 2]
    cases: list[tuple[FunctionModel, list[StackValue]]] = [
        (ListAppendModel(), [seq, 3]),
        (ListExtendModel(), [seq, [3, 4]]),
        (ListInsertModel(), [seq, 1, 99]),
        (ListClearModel(), [seq]),
        (ListSortModel(), [seq]),
        (ListReverseModel(), [seq]),
    ]
    for model, args in cases:
        result = model.apply(args, {}, _state())
        assert isinstance(result.value, SymbolicNone)


def test_symbolic_and_error_paths() -> None:
    """Symbolic and error path coverage for indexing/pop style methods."""
    ListPopModel().apply([], {}, _state())
    ListIndexModel().apply([], {}, _state())


def test_list_edge_case_empty_input() -> None:
    """Edge case: empty list input on contains model."""
    args: list[StackValue] = [[], 1]
    ListContainsModel().apply(args, {}, _state())


def test_list_copy_preserves_symbolic_elements_without_aliasing() -> None:
    """list.copy() returns a distinct container with the same retained items."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])

    result = ListCopyModel().apply([source], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value is not source
    assert result.value.concrete_items == [value]
    assert result.value.concrete_items is not source.concrete_items

    solver = z3.Solver()
    solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_slice_preserves_concrete_backed_symbolic_items() -> None:
    """Exact concrete slices should retain item identity for list results."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value, 1])

    result = slice_concrete_backed_sequence(source, slice(None, 1))

    assert isinstance(result, SymbolicList)
    assert getattr(result, "_type", None) == "list"
    assert result.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, result[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_getitem_symbolic_index_over_exact_items_selects_retained_values() -> None:
    """list.__getitem__ should preserve finite index-to-item relationships."""
    branch, branch_constraint = SymbolicValue.symbolic_int("list_getitem_branch")
    index = SymbolicValue.from_z3(branch.z3_int % 2, "list_getitem_index")
    source = SymbolicList.from_const([2, 1])

    result = ListGetitemModel().apply([source, index], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert "potential_exception" not in result.side_effects
    solver = z3.Solver()
    solver.add(branch_constraint, result.value.z3_int == 0)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 1, result.value.z3_int != 1)
    assert solver.check() == z3.unsat


def test_list_getitem_symbolic_index_over_exact_string_items_selects_strings() -> None:
    """list.__getitem__ should preserve finite string item relationships."""
    branch, branch_constraint = SymbolicValue.symbolic_int("list_getitem_string_branch")
    index = SymbolicValue.from_z3(branch.z3_int % 2, "list_getitem_string_index")
    source = SymbolicList.from_const(["a", "bb"])

    result = ListGetitemModel().apply([source, index], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert "potential_exception" not in result.side_effects
    solver = z3.Solver()
    solver.add(branch_constraint, result.value.z3_len == 0)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 1, result.value.z3_str != "bb")
    assert solver.check() == z3.unsat


def test_list_setitem_concrete_index_preserves_retained_value() -> None:
    """list.__setitem__ should retain exact replacement item metadata."""
    value, value_constraint = SymbolicValue.symbolic_int("setitem_value")
    source = SymbolicList.from_const([1, 2])

    result = ListSetitemModel().apply([source, 0, value], {}, _state())

    assert isinstance(result.value, SymbolicNone)
    assert "potential_exception" not in result.side_effects
    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [value, 2]

    solver = z3.Solver()
    solver.add(value_constraint, updated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_setitem_symbolic_in_bounds_index_preserves_array_relationship() -> None:
    """list.__setitem__ should update exactly one finite symbolic index."""
    branch, branch_constraint = SymbolicValue.symbolic_int("setitem_index_branch")
    index = SymbolicValue.from_z3(branch.z3_int % 2, "setitem_index")
    source = SymbolicList.from_const([1, 2])

    result = ListSetitemModel().apply([source, index, 9], {}, _state())

    assert "potential_exception" not in result.side_effects
    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)

    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 0, updated[0].z3_int != 9)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 0, updated[1].z3_int != 2)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 1, updated[0].z3_int != 1)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 1, updated[1].z3_int != 9)
    assert solver.check() == z3.unsat


def test_list_setitem_definite_out_of_range_raises_without_mutation() -> None:
    """list.__setitem__ should not emit a success mutation for definite IndexError."""
    source = SymbolicList.from_const([1])

    result = ListSetitemModel().apply([source, 1, 9], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "IndexError"
    assert "list_mutation" not in result.side_effects


def test_list_delitem_concrete_index_preserves_shifted_items() -> None:
    """list.__delitem__ should retain exact items after deleting a concrete index."""
    value, value_constraint = SymbolicValue.symbolic_int("delitem_value")
    source = SymbolicList.from_const([1, value, 3])

    result = ListDelitemModel().apply([source, 0], {}, _state())

    assert isinstance(result.value, SymbolicNone)
    assert "potential_exception" not in result.side_effects
    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [value, 3]

    solver = z3.Solver()
    solver.add(value_constraint, updated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_delitem_symbolic_in_bounds_index_preserves_shift_relationship() -> None:
    """list.__delitem__ should shift around a finite symbolic index exactly."""
    branch, branch_constraint = SymbolicValue.symbolic_int("delitem_index_branch")
    index = SymbolicValue.from_z3(branch.z3_int % 2, "delitem_index")
    source = SymbolicList.from_const([1, 2])

    result = ListDelitemModel().apply([source, index], {}, _state())

    assert "potential_exception" not in result.side_effects
    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert z3.is_true(z3.simplify(updated.z3_len == 1))

    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 0, updated[0].z3_int != 2)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int % 2 == 1, updated[0].z3_int != 1)
    assert solver.check() == z3.unsat


def test_list_delitem_definite_out_of_range_raises_without_mutation() -> None:
    """list.__delitem__ should not emit a success mutation for definite IndexError."""
    source = SymbolicList.from_const([1])

    result = ListDelitemModel().apply([source, 1], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "IndexError"
    assert "list_mutation" not in result.side_effects


def test_list_pop_default_preserves_last_symbolic_item_and_updates_list() -> None:
    """list.pop() should return the retained last item and remove it from metadata."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])

    result = ListPopModel().apply([source], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(value_constraint, result.value.z3_int != value.z3_int)
    assert solver.check() == z3.unsat

    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == []


def test_list_insert_front_preserves_inserted_symbolic_item() -> None:
    """list.insert(0, value) should retain the inserted item at index zero."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([1])

    result = ListInsertModel().apply([source, 0, value], {}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [value, 1]

    solver = z3.Solver()
    solver.add(value_constraint, updated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_extend_preserves_concrete_backed_suffix_items() -> None:
    """list.extend should retain suffix item relations when the extension is exact."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([1])
    extension = SymbolicList.from_const([value])

    result = ListExtendModel().apply([source, extension], {}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [1, value]

    solver = z3.Solver()
    solver.add(value_constraint, updated[1].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_reverse_preserves_exact_retained_order() -> None:
    """list.reverse should delegate exact retained reordering to core sequence semantics."""
    value, value_constraint = SymbolicValue.symbolic_int("reverse_value")
    source = SymbolicList.from_const([1, value])

    result = ListReverseModel().apply([source], {}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [value, 1]
    solver = z3.Solver()
    solver.add(value_constraint, updated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_sort_preserves_exact_retained_order() -> None:
    """list.sort should delegate exact retained sorting to core sequence semantics."""
    source = SymbolicList.from_const([2, 1, 3])

    result = ListSortModel().apply([source], {"reverse": True}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [3, 2, 1]


def test_list_remove_concrete_prefix_shifts_symbolic_suffix() -> None:
    """list.remove(concrete) should retain shifted symbolic suffix metadata."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([1, value])

    result = ListRemoveModel().apply([source, 1], {}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)
    assert updated.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, updated[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_remove_symbolic_bool_over_int_items_preserves_remaining_item() -> None:
    """list.remove should model bool/int equality and the remaining element."""
    needle, needle_constraint = SymbolicValue.symbolic_bool("needle")
    source = SymbolicList.from_const([0, 1])

    result = ListRemoveModel().apply([source, needle], {}, _state())

    missing = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(missing)
    solver = z3.Solver()
    solver.add(needle_constraint, missing["condition"])
    assert solver.check() == z3.unsat

    mutation = cast("dict[str, object] | None", result.side_effects.get("list_mutation"))
    assert mutation is not None
    updated = mutation["updated_list"]
    assert isinstance(updated, SymbolicList)

    solver = z3.Solver()
    solver.add(needle_constraint, z3.Not(needle.z3_bool), updated[0].z3_int != 1)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(needle_constraint, needle.z3_bool, updated[0].z3_int != 0)
    assert solver.check() == z3.unsat


def test_list_add_preserves_concrete_backed_symbolic_items() -> None:
    """list.__add__ should retain exact items when both operands are concrete-backed."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])
    empty = SymbolicList.from_const([])

    result = ListAddModel().apply([source, empty], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_add_preserves_concrete_backed_suffix_items() -> None:
    """list.__add__ should retain symbolic and concrete suffix item relations."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])
    suffix = SymbolicList.from_const([1])

    result = ListAddModel().apply([source, suffix], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [value, 1]

    solver = z3.Solver()
    solver.add(
        value_constraint,
        z3.Or(result.value[0].z3_int != value.z3_int, result.value[1].z3_int != 1),
    )
    assert solver.check() == z3.unsat


def test_list_mul_one_preserves_concrete_backed_symbolic_items() -> None:
    """list.__mul__(1) should retain exact shallow-copy element identity."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])

    result = ListMulModel().apply([source, 1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value is not source
    assert result.value.concrete_items == [value]

    solver = z3.Solver()
    solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_list_mul_two_preserves_repeated_symbolic_item_relation() -> None:
    """list.__mul__(2) should retain both repeated symbolic item relations."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])

    result = ListMulModel().apply([source, 2], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [value, value]

    solver = z3.Solver()
    solver.add(
        value_constraint,
        z3.Or(
            result.value[0].z3_int != value.z3_int,
            result.value[1].z3_int != value.z3_int,
        ),
    )
    assert solver.check() == z3.unsat


def test_list_contains_symbolic_value_over_exact_items_preserves_membership() -> None:
    """list.__contains__ should prove finite symbolic values are present."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_str=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        affinity_type="int",
    )
    source = SymbolicList.from_const([0, 1])

    result = ListContainsModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, z3.Not(result.value.z3_bool))
    assert solver.check() == z3.unsat


def test_list_contains_symbolic_value_over_exact_items_keeps_missing_branch() -> None:
    """list.__contains__ should keep false membership feasible when a value is absent."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_str=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        affinity_type="int",
    )
    source = SymbolicList.from_const([0])

    result = ListContainsModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, z3.Not(result.value.z3_bool))
    assert solver.check() == z3.sat


def test_list_count_symbolic_value_over_exact_items_preserves_positive_count() -> None:
    """list.count should prove finite symbolic values are present exactly once."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_str=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        affinity_type="int",
    )
    source = SymbolicList.from_const([0, 1])

    result = ListCountModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, result.value.z3_int != 1)
    assert solver.check() == z3.unsat


def test_list_count_symbolic_value_over_exact_items_keeps_zero_count() -> None:
    """list.count should keep zero feasible when a finite value is absent."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_str=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        affinity_type="int",
    )
    source = SymbolicList.from_const([0])

    result = ListCountModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(branch_constraint, result.value.z3_int == 0)
    assert solver.check() == z3.sat


def test_list_index_symbolic_value_over_exact_items_preserves_first_index() -> None:
    """list.index should resolve finite symbolic values to their exact first index."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_str=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        affinity_type="int",
    )
    source = SymbolicList.from_const([0, 1])

    result = ListIndexModel().apply([source, needle], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    missing = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(missing)
    solver = z3.Solver()
    solver.add(branch_constraint, missing["condition"])
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int == 0, result.value.z3_int != 0)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(branch_constraint, branch.z3_int != 0, result.value.z3_int != 1)
    assert solver.check() == z3.unsat


def test_list_index_symbolic_value_over_exact_items_keeps_missing_branch() -> None:
    """list.index should keep ValueError feasible when a finite value is absent."""
    branch, branch_constraint = SymbolicValue.symbolic_int("branch")
    needle = SymbolicValue(
        _name="needle",
        z3_int=z3.If(branch.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_str=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        affinity_type="int",
    )
    source = SymbolicList.from_const([0])

    result = ListIndexModel().apply([source, needle], {}, _state())

    missing = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(missing)
    solver = z3.Solver()
    solver.add(branch_constraint, missing["condition"])
    assert solver.check() == z3.sat


@pytest.mark.parametrize(
    ("model", "method_args"),
    [
        (ListAppendModel(), []),
        (ListAppendModel(), [1, 2]),
        (ListExtendModel(), []),
        (ListExtendModel(), [[1], [2]]),
        (ListInsertModel(), [0]),
        (ListInsertModel(), [0, 1, 2]),
        (ListRemoveModel(), []),
        (ListRemoveModel(), [1, 2]),
        (ListPopModel(), [0, 1]),
        (ListClearModel(), [1]),
        (ListSortModel(), [1]),
        (ListReverseModel(), [1]),
        (ListCopyModel(), [1]),
        (ListSetitemModel(), []),
        (ListSetitemModel(), [0]),
        (ListSetitemModel(), [0, 1, 2]),
        (ListDelitemModel(), []),
        (ListDelitemModel(), [0, 1]),
        (ListIndexModel(), []),
        (ListIndexModel(), [1, 0, 2, 3]),
        (ListCountModel(), []),
        (ListCountModel(), [1, 2]),
    ],
)
def test_list_public_methods_reject_invalid_positional_arity(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Public list methods report TypeError for CPython-invalid positional forms."""
    receiver = SymbolicList.empty("receiver")

    result = model.apply([receiver, *method_args], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    ("model", "method_args"),
    [
        (ListAppendModel(), [1]),
        (ListExtendModel(), [[1]]),
        (ListInsertModel(), [0, 1]),
        (ListRemoveModel(), [1]),
        (ListPopModel(), []),
        (ListClearModel(), []),
        (ListReverseModel(), []),
        (ListCopyModel(), []),
        (ListSetitemModel(), [0, 1]),
        (ListDelitemModel(), [0]),
        (ListIndexModel(), [1]),
        (ListCountModel(), [1]),
    ],
)
def test_list_public_methods_reject_keywords(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """List methods other than sort reject keyword arguments in CPython."""
    result = model.apply(
        [SymbolicList.empty("receiver"), *method_args], {"unexpected": 1}, _state()
    )
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_list_sort_accepts_supported_keyword_only_parameters() -> None:
    """list.sort accepts the key and reverse keyword-only parameters."""
    result = ListSortModel().apply(
        [SymbolicList.empty("receiver")], {"key": None, "reverse": True}, _state()
    )

    assert "raised_exception" not in result.side_effects
