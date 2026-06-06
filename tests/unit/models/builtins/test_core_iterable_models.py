from __future__ import annotations

from typing import cast

import z3

from pysymex.typing import StackValue
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.containers.iterator_sources import (
    EnumerateIteratorSource,
    FilterIteratorSource,
    ZipIteratorSource,
)
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.collections import ListModel, TupleModel
from pysymex.models.builtins.core.conversions.numeric import ComplexModel, SliceModel
from pysymex.models.builtins.core.iterables import (
    EnumerateModel,
    FilterModel,
    MapModel,
    SortedModel,
    SumModel,
    ZipModel,
)
from pysymex.models.builtins.core.iterator_items import concrete_iterable_items
from pysymex.models.builtins.core.type_checks import IsinstanceModel, PrintModel, TypeModel
from pysymex.models.builtins.base import is_raised_exception_effect
from tests.unit.models.builtins.core_model_helpers import state


class TestPrintModel:
    """Test suite for pysymex.models.builtins.core.PrintModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        result = PrintModel().apply(["x"], {}, state())
        assert isinstance(result.value, SymbolicNone)

    def test_accepts_supported_output_keywords_and_rejects_unknown_keyword(self) -> None:
        kwargs: dict[str, StackValue] = {"sep": "-", "end": ""}
        assert "raised_exception" not in PrintModel().apply(["x"], kwargs, state()).side_effects
        invalid = PrintModel().apply(["x"], {"unknown": True}, state())
        assert is_raised_exception_effect(invalid.side_effects.get("raised_exception"))

    def test_rejects_definite_invalid_separator_and_terminator(self) -> None:
        invalid_keywords: list[dict[str, StackValue]] = [{"sep": 1}, {"end": 1}]
        for kwargs in invalid_keywords:
            result = PrintModel().apply(["x"], kwargs, state())

            assert is_raised_exception_effect(result.side_effects.get("raised_exception"))


class TestTypeModel:
    """Test suite for pysymex.models.builtins.core.TypeModel."""

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """type() raises TypeError in CPython."""
        result = TypeModel().apply([], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_apply_one_arg_is_supported(self) -> None:
        """type(value) remains a modeled call path."""
        result = TypeModel().apply([1], {}, state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value is int

    def test_invalid_three_argument_construction_emits_type_error(self) -> None:
        invalid = TypeModel().apply([1, (), {}], {}, state())

        assert is_raised_exception_effect(invalid.side_effects.get("raised_exception"))


class TestIsinstanceModel:
    """Test suite for pysymex.models.builtins.core.IsinstanceModel."""

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """isinstance() raises TypeError in CPython."""
        result = IsinstanceModel().apply([], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_concrete_single_type_is_exact_and_invalid_type_fails(self) -> None:
        valid = IsinstanceModel().apply([1, int], {}, state())
        invalid = IsinstanceModel().apply([1, 1], {}, state())

        assert valid.value is True
        assert is_raised_exception_effect(invalid.side_effects.get("raised_exception"))


class TestSortedModel:
    """Test suite for pysymex.models.builtins.core.SortedModel."""

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """sorted() raises TypeError in CPython."""
        result = SortedModel().apply([], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_apply_with_extra_arg_emits_type_error_side_effect(self) -> None:
        """sorted(iterable, positional_extra) raises TypeError in CPython."""
        result = SortedModel().apply([[1], [2]], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_keyword_options_are_accepted_but_unknown_keywords_are_rejected(self) -> None:
        kwargs: dict[str, StackValue] = {"reverse": True}
        assert "raised_exception" not in SortedModel().apply([[2, 1]], kwargs, state()).side_effects
        invalid = SortedModel().apply([[2, 1]], {"unknown": True}, state())
        assert is_raised_exception_effect(invalid.side_effects.get("raised_exception"))

    def test_concrete_values_are_sorted_and_non_iterables_fail(self) -> None:
        result = SortedModel().apply([[2, 1]], {}, state())
        invalid = SortedModel().apply([1], {}, state())

        assert isinstance(result.value, SymbolicList)
        assert result.value.concrete_items == [1, 2]
        assert is_raised_exception_effect(invalid.side_effects.get("raised_exception"))

    def test_single_heap_backed_symbolic_item_is_preserved(self) -> None:
        value, value_constraint = SymbolicValue.symbolic_int("value")
        source = SymbolicList.from_const([value])
        handle = SymbolicObject("items", 101, z3.IntVal(101), {101})
        vm_state = state().store_heap(101, source)

        result = SortedModel().apply([handle], {}, vm_state)

        assert isinstance(result.value, SymbolicList)
        assert result.value.concrete_items == [value]

        solver = z3.Solver()
        solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
        assert solver.check() == z3.unsat

    def test_heap_backed_symbolic_constant_items_are_sorted(self) -> None:
        source = SymbolicList.from_const(
            [SymbolicValue.from_const(3), SymbolicValue.from_const(1), SymbolicValue.from_const(2)]
        )
        handle = SymbolicObject("items", 102, z3.IntVal(102), {102})
        vm_state = state().store_heap(102, source)

        result = SortedModel().apply([handle], {}, vm_state)

        assert isinstance(result.value, SymbolicList)
        concrete_items = result.value.concrete_items
        assert concrete_items is not None
        assert [getattr(item, "value", None) for item in concrete_items] == [1, 2, 3]
        assert z3.is_true(z3.simplify(result.value.z3_len == 3))


class TestSumModel:
    """Test suite for pysymex.models.builtins.core.SumModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        values: list[StackValue] = [1, 2, 3]
        args: list[StackValue] = [values]
        assert SumModel().apply(args, {}, state()).value == 6

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """sum() raises TypeError in CPython."""
        result = SumModel().apply([], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_apply_with_too_many_args_emits_type_error_side_effect(self) -> None:
        """sum(iterable, start, extra) raises TypeError in CPython."""
        result = SumModel().apply([[1], 0, 1], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_named_start_is_applied_and_duplicate_binding_is_rejected(self) -> None:
        kwargs: dict[str, StackValue] = {"start": 3}
        assert SumModel().apply([[1, 2]], kwargs, state()).value == 6
        invalid = SumModel().apply([[1, 2], 3], kwargs, state())
        assert is_raised_exception_effect(invalid.side_effects.get("raised_exception"))

    def test_text_elements_emit_type_error_side_effect(self) -> None:
        invalid = SumModel().apply([["a"]], {}, state())

        assert is_raised_exception_effect(invalid.side_effects.get("raised_exception"))

    def test_symbolic_int_items_constrain_sum_result(self) -> None:
        value, value_constraint = SymbolicValue.symbolic_int("value")

        result = SumModel().apply([[value, 1]], {}, state())

        assert isinstance(result.value, SymbolicValue)
        unsat_solver = z3.Solver()
        unsat_solver.add(
            value_constraint,
            *result.constraints,
            result.value.z3_int == 0,
            value.z3_int == 0,
        )
        sat_solver = z3.Solver()
        sat_solver.add(
            value_constraint,
            *result.constraints,
            result.value.z3_int == 0,
            value.z3_int == -1,
        )

        assert unsat_solver.check() == z3.unsat
        assert sat_solver.check() == z3.sat


class TestEnumerateModel:
    """Test suite for pysymex.models.builtins.core.EnumerateModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        iterable: list[StackValue] = [1, 2]
        args: list[StackValue] = [iterable]
        result = EnumerateModel().apply(args, {}, state())
        assert result.value is not None

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """enumerate() raises TypeError in CPython."""
        result = EnumerateModel().apply([], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_apply_preserves_concrete_items(self) -> None:
        """Concrete enumerate inputs materialize exact pairs when consumed."""
        iterable = SymbolicList.from_const([10, 20])
        vm_state = state()

        result = EnumerateModel().apply([iterable], {}, vm_state)

        assert isinstance(result.value, SymbolicIterator)
        assert isinstance(result.value.iterable, EnumerateIteratorSource)
        assert concrete_iterable_items(result.value, vm_state) == [(0, 10), (1, 20)]

    def test_apply_resolves_heap_backed_concrete_list(self) -> None:
        """Concrete lists lowered to heap handles materialize exact pairs when consumed."""
        vm_state = state()
        iterable = SymbolicList.from_const([10, 20])
        handle = SymbolicObject("list_42", 42, z3.IntVal(42), {42})
        vm_state.store_heap(42, iterable)

        result = EnumerateModel().apply([handle], {}, vm_state)

        assert isinstance(result.value, SymbolicIterator)
        assert isinstance(result.value.iterable, EnumerateIteratorSource)
        assert concrete_iterable_items(result.value, vm_state) == [(0, 10), (1, 20)]

    def test_named_iterable_and_start_preserve_concrete_pairs(self) -> None:
        kwargs: dict[str, StackValue] = {"iterable": [10, 20], "start": 5}
        vm_state = state()
        result = EnumerateModel().apply([], kwargs, vm_state)

        assert isinstance(result.value, SymbolicIterator)
        assert isinstance(result.value.iterable, EnumerateIteratorSource)
        assert concrete_iterable_items(result.value, vm_state) == [(5, 10), (6, 20)]

    def test_duplicate_or_unknown_keyword_binding_emits_type_error(self) -> None:
        duplicate = EnumerateModel().apply([[1], 2], {"start": 3}, state())
        unknown = EnumerateModel().apply([[1]], {"unknown": 3}, state())
        assert is_raised_exception_effect(duplicate.side_effects.get("raised_exception"))
        assert is_raised_exception_effect(unknown.side_effects.get("raised_exception"))


class TestZipModel:
    """Test suite for pysymex.models.builtins.core.ZipModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        first: list[StackValue] = [1]
        second: list[StackValue] = [2]
        args: list[StackValue] = [first, second]
        result = ZipModel().apply(args, {}, state())
        assert result.value is not None

    def test_apply_preserves_shortest_concrete_pairs(self) -> None:
        """Concrete zip inputs materialize CPython shortest-length pairs when consumed."""
        first = SymbolicList.from_const([1, 2, 3])
        second = SymbolicList.from_const([4])
        vm_state = state()

        result = ZipModel().apply([first, second], {}, vm_state)

        assert isinstance(result.value, SymbolicIterator)
        assert isinstance(result.value.iterable, ZipIteratorSource)
        assert concrete_iterable_items(result.value, vm_state) == [(1, 4)]

    def test_strict_false_is_accepted_and_unknown_keyword_is_rejected(self) -> None:
        strict_kwargs: dict[str, StackValue] = {"strict": False}
        vm_state = state()
        result = ZipModel().apply([[1], [2]], strict_kwargs, vm_state)
        invalid = ZipModel().apply([[1], [2]], {"unknown": False}, vm_state)

        assert isinstance(result.value, SymbolicIterator)
        assert isinstance(result.value.iterable, ZipIteratorSource)
        assert concrete_iterable_items(result.value, vm_state) == [(1, 2)]
        assert is_raised_exception_effect(invalid.side_effects.get("raised_exception"))

    def test_strict_true_reports_known_length_mismatch(self) -> None:
        valid = ZipModel().apply([[1], [2]], {"strict": True}, state())
        invalid = ZipModel().apply([[1], [2, 3]], {"strict": True}, state())

        assert isinstance(valid.value, SymbolicIterator)
        assert valid.value.iterable == [(1, 2)]
        effect = invalid.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "ValueError"


class TestMapModel:
    """Test suite for pysymex.models.builtins.core.MapModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        iterable: list[StackValue] = [1]
        args: list[StackValue] = [str, iterable]
        result = MapModel().apply(args, {}, state())
        assert result.value is not None

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """map() raises TypeError in CPython."""
        result = MapModel().apply([], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))


class TestFilterModel:
    """Test suite for pysymex.models.builtins.core.FilterModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        iterable: list[StackValue] = [0, 1]
        args: list[StackValue] = [bool, iterable]
        result = FilterModel().apply(args, {}, state())
        assert result.value is not None

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """filter() raises TypeError in CPython."""
        result = FilterModel().apply([], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_filter_none_single_symbolic_item_constrains_length(self) -> None:
        value, value_constraint = SymbolicValue.symbolic_int("value")
        source = SymbolicList.from_const([value])
        handle = SymbolicObject("items", 101, z3.IntVal(101), {101})
        vm_state = state().store_heap(101, source)

        result = FilterModel().apply([None, handle], {}, vm_state)

        assert isinstance(result.value, SymbolicIterator)
        assert isinstance(result.value.iterable, FilterIteratorSource)

        list_result = ListModel().apply([result.value], {}, vm_state)
        assert isinstance(list_result.value, SymbolicList)
        assert list_result.value.concrete_items is None

        positive_len_solver = z3.Solver()
        positive_len_solver.add(
            value_constraint,
            *list_result.constraints,
            list_result.value.z3_len > 0,
            value.z3_int == 0,
        )
        zero_len_solver = z3.Solver()
        zero_len_solver.add(
            value_constraint,
            *list_result.constraints,
            list_result.value.z3_len == 0,
            value.z3_int == 0,
        )

        assert positive_len_solver.check() == z3.unsat
        assert zero_len_solver.check() == z3.sat


class TestListModel:
    """Test suite for pysymex.models.builtins.core.ListModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        values: list[StackValue] = [1, 2]
        args: list[StackValue] = [values]
        ListModel().apply(args, {}, state())

    def test_definite_non_iterable_emits_type_error_side_effect(self) -> None:
        result = ListModel().apply([1], {}, state())

        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_apply_copies_heap_backed_symbolic_list_elements(self) -> None:
        """list(heap-backed-list) should preserve elements without aliasing the source."""
        value, value_constraint = SymbolicValue.symbolic_int("value")
        source = SymbolicList.from_const([value])
        handle = SymbolicObject("items", 101, z3.IntVal(101), {101})
        vm_state = state().store_heap(101, source)

        result = ListModel().apply([handle], {}, vm_state)

        assert isinstance(result.value, SymbolicList)
        assert result.value is not source
        assert result.value.concrete_items == [value]

        solver = z3.Solver()
        solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
        assert solver.check() == z3.unsat

    def test_apply_materializes_and_consumes_exact_symbolic_iterator(self) -> None:
        value, value_constraint = SymbolicValue.symbolic_int("value")
        iterator = SymbolicIterator("items", SymbolicList.from_const([value]))

        result = ListModel().apply([iterator], {}, state())

        assert isinstance(result.value, SymbolicList)
        assert result.value.concrete_items == [value]
        mutation = cast("dict[str, object]", result.side_effects.get("iterator_mutation"))
        assert isinstance(mutation, dict)
        updated = mutation["updated_iterator"]
        assert isinstance(updated, SymbolicIterator)
        assert updated.index == 1

        solver = z3.Solver()
        solver.add(value_constraint, result.value[0].z3_int != value.z3_int)
        assert solver.check() == z3.unsat


class TestTupleModel:
    """Test suite for pysymex.models.builtins.core.TupleModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        value: list[StackValue] = [1, 2]
        args: list[StackValue] = [value]
        assert TupleModel().apply(args, {}, state()).value == tuple(value)


class TestComplexModel:
    """Test suite for pysymex.models.builtins.core.ComplexModel."""

    def test_apply_no_args(self) -> None:
        """Test apply behavior with no args."""
        result = ComplexModel().apply([], {}, state())
        assert isinstance(result.value, SymbolicValue)

    def test_apply_with_args(self) -> None:
        """Test apply behavior with args."""
        args: list[StackValue] = [1, 2]
        result = ComplexModel().apply(args, {}, state())
        assert isinstance(result.value, SymbolicValue)


class TestSliceModel:
    """Test suite for pysymex.models.builtins.core.SliceModel."""

    def test_apply_no_args_emits_type_error_side_effect(self) -> None:
        """slice() raises TypeError in CPython."""
        result = SliceModel().apply([], {}, state())
        assert is_raised_exception_effect(result.side_effects.get("raised_exception"))

    def test_apply_with_args(self) -> None:
        """Test apply behavior with args."""
        args: list[StackValue] = [0, 10, 2]
        result = SliceModel().apply(args, {}, state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == slice(0, 10, 2)
