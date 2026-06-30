from __future__ import annotations

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.numeric.float import SymbolicFloat
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.constructors.collections import NoneModel
from pysymex._internal.models.builtins.conversions.boolean import BoolModel
from pysymex._internal.models.builtins.conversions.numeric import ComplexModel, FloatModel
from pysymex._internal.models.builtins.conversions.scalar import IntModel, StrModel
from pysymex._internal.models.builtins.iteration.aggregates import SumModel
from pysymex._internal.models.builtins.numeric.abs import AbsModel
from pysymex._internal.models.builtins.numeric.max import MaxModel
from pysymex._internal.models.builtins.numeric.min import MinModel
from pysymex._internal.models.builtins.sequences.len import LenModel
from pysymex._internal.models.builtins.sequences.range import RangeModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.typing.protocols import StackValue
from tests.unit.models.builtins.core_model_helpers import state


def _raised_exception_type(result: ModelResult) -> str | None:
    raised = result.side_effects.get("raised_exception")
    if not SideEffects.is_raised_exception(raised):
        return None
    return raised["exception_type"]


class TestLenModel:
    """Test suite for pysymex._internal.models.builtins.core.LenModel."""

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """len() raises TypeError in CPython."""
        result = LenModel().apply([], {}, state())
        assert _raised_exception_type(result) == "TypeError"

    def test_apply_resolves_symbolic_object_container_length(self) -> None:
        """len(symbolic-list-object) must share the underlying list length."""
        symbolic_list, list_constraint = SymbolicList.symbolic("items")
        obj = SymbolicObject("items", 101, z3.IntVal(101), {101})
        vm_state = VMState(memory={101: symbolic_list})

        result = LenModel().apply([obj], {}, vm_state)

        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(list_constraint, *result.constraints)
        solver.add(result.value.z3_int != symbolic_list.z3_len)
        assert solver.check() == z3.unsat

    def test_apply_returns_concrete_len_for_concrete_backed_symbolic_list_object(
        self,
    ) -> None:
        """len(heap-backed list literal) should expose the exact CPython length."""
        concrete_list = SymbolicList.from_const([1, 2, 3])
        obj = SymbolicObject("items", 102, z3.IntVal(102), {102})
        vm_state = VMState(memory={102: concrete_list})

        result = LenModel().apply([obj], {}, vm_state)

        assert result.value == 3
        assert result.constraints == ()

    def test_apply_returns_concrete_len_for_symbolic_constant_tuple(self) -> None:
        """len(SymbolicValue.from_const(tuple)) must match CPython's tuple length."""
        obj = SymbolicValue.from_const((10, 20, 30))

        result = LenModel().apply([obj], {}, state())

        assert result.value == 3
        assert result.constraints == ()

    def test_apply_int_emits_type_error_side_effect(self) -> None:
        """len(int) raises TypeError in CPython."""
        result = LenModel().apply([SymbolicValue.from_const(1)], {}, state())

        assert "raised_exception" in result.side_effects


class TestRangeModel:
    """Test suite for pysymex._internal.models.builtins.core.RangeModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        args: list[StackValue] = [3]
        result = RangeModel().apply(args, {}, state())
        assert result.value is not None

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """range() raises TypeError in CPython."""
        result = RangeModel().apply([], {}, state())
        assert _raised_exception_type(result) == "TypeError"

    def test_apply_unrolls_small_bounded_ranges(self) -> None:
        """Test small concrete ranges avoid quantified constraints."""
        result = RangeModel().apply([1, 4], {}, state())
        assert result.value is not None
        assert getattr(result.value, "_type", None) == "range"
        assert not any(z3.is_quantifier(constraint) for constraint in result.constraints)

    def test_large_concrete_range_retains_compact_runtime_type_and_length(self) -> None:
        """Large ranges stay compact while preserving exact range identity and length."""
        result = RangeModel().apply([1_000_000_000], {}, state())

        assert isinstance(result.value, SymbolicList)
        assert result.value.concrete_items is None
        assert getattr(result.value, "_type", None) == "range"
        solver = z3.Solver()
        solver.add(*result.constraints, result.value.z3_len != 1_000_000_000)
        assert solver.check() == z3.unsat

    def test_symbolic_range_uses_exact_element_progression_without_lambda_axiom(self) -> None:
        """Observed symbolic range elements stay exact without quantified constraints."""
        stop, _ = SymbolicValue.symbolic_int("stop")
        result = RangeModel().apply([stop], {}, state())

        assert isinstance(result.value, SymbolicList)
        assert not any(z3.is_quantifier(constraint) for constraint in result.constraints)
        first = result.value[0]
        assert z3.is_true(simplify_expr(first.z3_int == 0))

    def test_symbolic_negative_step_range_counts_down_from_positive_start(self) -> None:
        """range(n, 0, -1) has exactly n items when n is positive."""
        start, start_constraint = SymbolicValue.symbolic_int("range_down_start")
        result = RangeModel().apply([start, 0, -1], {}, state())

        assert isinstance(result.value, SymbolicList)
        solver = z3.Solver()
        solver.add(start_constraint, *result.constraints)
        solver.add(start.z3_int > 0)
        solver.add(result.value.z3_len != start.z3_int)
        assert solver.check() == z3.unsat

    def test_symbolic_negative_step_range_is_empty_when_direction_misses_stop(self) -> None:
        """range(n, 0, -1) is empty when n is not positive."""
        start, start_constraint = SymbolicValue.symbolic_int("range_empty_down_start")
        result = RangeModel().apply([start, 0, -1], {}, state())

        assert isinstance(result.value, SymbolicList)
        solver = z3.Solver()
        solver.add(start_constraint, *result.constraints)
        solver.add(start.z3_int <= 0)
        solver.add(result.value.z3_len != 0)
        assert solver.check() == z3.unsat

    def test_symbolic_positive_step_range_counts_up_to_positive_stop(self) -> None:
        """range(0, n, 1) keeps the existing positive-step length relation."""
        stop, stop_constraint = SymbolicValue.symbolic_int("range_up_stop")
        result = RangeModel().apply([0, stop, 1], {}, state())

        assert isinstance(result.value, SymbolicList)
        solver = z3.Solver()
        solver.add(stop_constraint, *result.constraints)
        solver.add(stop.z3_int > 0)
        solver.add(result.value.z3_len != stop.z3_int)
        assert solver.check() == z3.unsat

    def test_concrete_invalid_argument_and_zero_step_emit_exceptions(self) -> None:
        invalid_type = RangeModel().apply([1.0], {}, state())
        zero_step = RangeModel().apply([1, 4, 0], {}, state())

        assert _raised_exception_type(invalid_type) == "TypeError"
        assert _raised_exception_type(zero_step) == "ValueError"

    def test_concrete_symbolic_non_integer_argument_emits_type_error(self) -> None:
        result = RangeModel().apply([SymbolicValue.from_const(1.0)], {}, state())

        assert _raised_exception_type(result) == "TypeError"


class TestAbsModel:
    """Test suite for pysymex._internal.models.builtins.core.AbsModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        value = -5
        assert AbsModel().apply([value], {}, state()).value == abs(value)

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """abs() raises TypeError in CPython."""
        result = AbsModel().apply([], {}, state())
        assert _raised_exception_type(result) == "TypeError"

    def test_definite_non_numeric_inputs_emit_type_error_side_effect(self) -> None:
        assert _raised_exception_type(AbsModel().apply(["x"], {}, state())) == "TypeError"
        assert (
            _raised_exception_type(AbsModel().apply([SymbolicString.from_const("x")], {}, state()))
            == "TypeError"
        )


class TestMinModel:
    """Test suite for pysymex._internal.models.builtins.core.MinModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        values: list[StackValue] = [4, 1, 6]
        assert MinModel().apply(values, {}, state()).value == 1

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """min() raises TypeError in CPython."""
        result = MinModel().apply([], {}, state())
        assert _raised_exception_type(result) == "TypeError"

    def test_apply_empty_sequence_emits_value_error_side_effect(self) -> None:
        """min([]) raises ValueError in CPython."""
        result = MinModel().apply([[]], {}, state())
        assert "raised_exception" in result.side_effects

    def test_apply_empty_symbolic_list_emits_value_error_side_effect(self) -> None:
        """VM-built empty lists also raise ValueError through min()."""
        result = MinModel().apply([SymbolicList.empty("items")], {}, state())
        assert "raised_exception" in result.side_effects

    def test_apply_empty_heap_list_handle_emits_value_error_side_effect(self) -> None:
        """Scanner BUILD_LIST handles are resolved before min() checks emptiness."""
        values = SymbolicList.from_const([])
        obj = SymbolicObject("items", 101, z3.IntVal(101), {101})
        result = MinModel().apply([obj], {}, VMState(memory={101: values}))
        assert "raised_exception" in result.side_effects

    def test_empty_default_is_preserved_with_key(self) -> None:
        kwargs: dict[str, StackValue] = {"default": 9, "key": str}
        assert MinModel().apply([[]], kwargs, state()).value == 9

    def test_nontrivial_key_is_not_concretized_and_invalid_default_is_rejected(self) -> None:
        keyed = MinModel().apply([10, 2], {"key": str}, state())
        invalid = MinModel().apply([10, 2], {"default": 9}, state())
        unknown = MinModel().apply([[1]], {"unknown": 9}, state())
        assert isinstance(keyed.value, SymbolicValue)
        assert _raised_exception_type(invalid) == "TypeError"
        assert _raised_exception_type(unknown) == "TypeError"


class TestMaxModel:
    """Test suite for pysymex._internal.models.builtins.core.MaxModel."""

    def test_apply(self) -> None:
        """Test apply behavior."""
        values: list[StackValue] = [4, 1, 6]
        assert MaxModel().apply(values, {}, state()).value == 6

    def test_apply_without_args_emits_type_error_side_effect(self) -> None:
        """max() raises TypeError in CPython."""
        result = MaxModel().apply([], {}, state())
        assert _raised_exception_type(result) == "TypeError"

    def test_apply_empty_sequence_emits_value_error_side_effect(self) -> None:
        """max([]) raises ValueError in CPython."""
        result = MaxModel().apply([[]], {}, state())
        assert "raised_exception" in result.side_effects

    def test_apply_empty_symbolic_list_emits_value_error_side_effect(self) -> None:
        """VM-built empty lists also raise ValueError through max()."""
        result = MaxModel().apply([SymbolicList.empty("items")], {}, state())
        assert "raised_exception" in result.side_effects

    def test_apply_empty_heap_list_handle_emits_value_error_side_effect(self) -> None:
        """Scanner BUILD_LIST handles are resolved before max() checks emptiness."""
        values = SymbolicList.from_const([])
        obj = SymbolicObject("items", 101, z3.IntVal(101), {101})
        result = MaxModel().apply([obj], {}, VMState(memory={101: values}))
        assert "raised_exception" in result.side_effects

    def test_empty_default_is_preserved_with_key(self) -> None:
        kwargs: dict[str, StackValue] = {"default": 9, "key": str}
        assert MaxModel().apply([[]], kwargs, state()).value == 9

    def test_nontrivial_key_is_not_concretized_and_invalid_default_is_rejected(self) -> None:
        keyed = MaxModel().apply([10, 2], {"key": str}, state())
        invalid = MaxModel().apply([10, 2], {"default": 9}, state())
        unknown = MaxModel().apply([[1]], {"unknown": 9}, state())
        assert isinstance(keyed.value, SymbolicValue)
        assert _raised_exception_type(invalid) == "TypeError"
        assert _raised_exception_type(unknown) == "TypeError"


class TestScalarModels:
    def test_int(self) -> None:
        value = "12"
        assert IntModel().apply([value], {}, state()).value == int(value)

    def test_int_invalid_literal_emits_value_error_side_effect(self) -> None:
        result = IntModel().apply(["12x"], {}, state())

        assert _raised_exception_type(result) == "ValueError"

    def test_int_invalid_symbolic_string_literal_emits_value_error_side_effect(self) -> None:
        result = IntModel().apply([SymbolicString.from_const("12x")], {}, state())

        assert _raised_exception_type(result) == "ValueError"

    def test_int_parses_path_forced_symbolic_string_literal(self) -> None:
        text, text_constraint = SymbolicString.symbolic("int_text")
        length_slot = z3.Int("len_int_text_int")
        vm_state = VMState(
            path_constraints=[
                text_constraint,
                length_slot == z3.Length(text.z3_str),
                length_slot == 2,
                z3.SubString(text.z3_str, 0, 1) == z3.StringVal("4"),
                z3.SubString(text.z3_str, 1, 1) == z3.StringVal("2"),
            ],
            pc=12,
        )

        result = IntModel().apply([text], {}, vm_state)

        assert result.value == 42
        assert result.constraints == ()
        assert "potential_exception" not in result.side_effects

    def test_int_definite_type_failures_are_modeled(self) -> None:
        invalid_base = IntModel().apply([SymbolicString.from_const("10")], {"base": 1.5}, state())
        invalid_source = IntModel().apply([None], {}, state())

        assert _raised_exception_type(invalid_base) == "TypeError"
        assert _raised_exception_type(invalid_source) == "TypeError"

    def test_str(self) -> None:
        value = 12
        assert StrModel().apply([value], {}, state()).value == str(value)

    def test_bool(self) -> None:
        value = 0
        assert BoolModel().apply([value], {}, state()).value == bool(value)

    def test_float(self) -> None:
        result = FloatModel().apply([], {}, state())
        assert isinstance(result.value, SymbolicValue)

    def test_float_invalid_literal_emits_value_error_side_effect(self) -> None:
        result = FloatModel().apply(["not-a-float"], {}, state())

        assert _raised_exception_type(result) == "ValueError"

    def test_float_invalid_symbolic_string_literal_emits_value_error_side_effect(self) -> None:
        result = FloatModel().apply([SymbolicString.from_const("not-a-float")], {}, state())

        assert _raised_exception_type(result) == "ValueError"

    def test_float_parses_bytes_and_rejects_definite_invalid_inputs(self) -> None:
        parsed = FloatModel().apply([b"1.25"], {}, state())
        invalid_literal = FloatModel().apply([b"bad"], {}, state())
        invalid_type = FloatModel().apply([None], {}, state())

        assert isinstance(parsed.value, SymbolicFloat)
        assert z3.is_true(
            simplify_expr(z3.fpEQ(parsed.value.z3_expr, z3.FPVal(1.25, z3.Float64())))
        )
        assert _raised_exception_type(invalid_literal) == "ValueError"
        assert _raised_exception_type(invalid_type) == "TypeError"

    def test_int_explicit_base_keyword_matches_cpython_and_rejects_invalid_binding(self) -> None:
        kwargs: dict[str, StackValue] = {"base": 2}
        assert IntModel().apply(["10"], kwargs, state()).value == 2
        assert _raised_exception_type(IntModel().apply([], kwargs, state())) == "TypeError"
        assert (
            _raised_exception_type(IntModel().apply(["10"], {"unknown": 2}, state())) == "TypeError"
        )

    def test_str_named_object_and_codec_match_cpython_and_reject_duplicates(self) -> None:
        assert StrModel().apply([], {"object": 7}, state()).value == "7"
        assert StrModel().apply([b"x"], {"encoding": "utf-8"}, state()).value == "x"
        duplicate = StrModel().apply([7], {"object": 7}, state())
        assert _raised_exception_type(duplicate) == "TypeError"

    def test_str_byte_codec_arguments_reject_definite_invalid_types(self) -> None:
        invalid_encoding = StrModel().apply([b"x"], {"encoding": 1}, state())
        invalid_errors = StrModel().apply([b"x"], {"errors": 1}, state())

        assert _raised_exception_type(invalid_encoding) == "TypeError"
        assert _raised_exception_type(invalid_errors) == "TypeError"

    def test_complex_keyword_parts_are_accepted_and_invalid_binding_is_rejected(self) -> None:
        kwargs: dict[str, StackValue] = {"real": 1, "imag": 2}
        concrete = ComplexModel().apply([], kwargs, state())
        assert isinstance(concrete.value, SymbolicValue)
        assert concrete.value.value == complex(real=1, imag=2)
        assert "raised_exception" not in concrete.side_effects
        duplicate = ComplexModel().apply([1], {"real": 2}, state())
        unknown = ComplexModel().apply([], {"unknown": 1}, state())
        assert _raised_exception_type(duplicate) == "TypeError"
        assert _raised_exception_type(unknown) == "TypeError"

    def test_complex_concrete_parse_failures_are_modeled(self) -> None:
        malformed = ComplexModel().apply(["bad"], {}, state())
        invalid_imag = ComplexModel().apply([1, "x"], {}, state())

        assert _raised_exception_type(malformed) == "ValueError"
        assert _raised_exception_type(invalid_imag) == "TypeError"

    def test_none(self) -> None:
        result = NoneModel().apply([], {}, state())
        assert isinstance(result.value, SymbolicNone)

    def test_none_type_rejects_arguments(self) -> None:
        result = NoneModel().apply([1], {}, state())

        assert _raised_exception_type(result) == "TypeError"


def test_core_model_edge_paths() -> None:
    """Exercise edge and error-adjacent model paths with valid stack values."""
    sum_items: list[StackValue] = [1, 2]
    sum_args: list[StackValue] = [sum_items]

    assert AbsModel().apply([-1], {}, state()).value == 1
    assert IntModel().apply(["7"], {}, state()).value == 7
    assert StrModel().apply([7], {}, state()).value == "7"
    assert BoolModel().apply([1], {}, state()).value is True
    assert SumModel().apply(sum_args, {}, state()).value == 3
