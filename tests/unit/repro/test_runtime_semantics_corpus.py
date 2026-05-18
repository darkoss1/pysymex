"""Tests for real-world Python semantics corpus edge cases."""

from __future__ import annotations

from collections.abc import Callable

from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
from tests.repro import runtime_semantics_corpus as corpus


def _build_executor() -> SymbolicExecutor:
    """Create a deterministic executor configuration for corpus smoke checks."""
    config = ExecutionConfig(
        max_paths=128,
        max_depth=128,
        max_iterations=8192,
        timeout_seconds=20.0,
        enable_chtd=False,
        enable_h_acceleration=False,
        enable_abstract_interpretation=False,
        enable_cross_function=False,
        enable_type_inference=False,
        use_loop_analysis=False,
        enable_caching=False,
        enable_fp_filtering=False,
        enable_solver_cache=False,
        detect_overflow=True,
        verbose=False,
    )
    return SymbolicExecutor(config=config)


def _all_case_functions() -> list[Callable[[], object]]:
    """Return all runtime semantics corpus functions in deterministic order."""
    return [
        corpus.case01_late_binding_lambdas,
        corpus.case02_default_bound_lambdas,
        corpus.case03_list_alias_append_len,
        corpus.case04_list_alias_nested_mutation,
        corpus.case05_dict_alias_shared_update,
        corpus.case06_shallow_copy_shares_nested,
        corpus.case07_deep_copy_isolated_nested,
        corpus.case08_mutable_default_persists,
        corpus.case09_safe_default_isolated,
        corpus.case10_nonlocal_counter_progression,
        corpus.case11_closure_factory_independence,
        corpus.case12_list_slice_assignment,
        corpus.case13_extended_unpacking_middle,
        corpus.case14_negative_index_lookup,
        corpus.case15_list_multiply_alias_pitfall,
        corpus.case16_list_comprehension_scope_isolated,
        corpus.case17_setdefault_alias_behavior,
        corpus.case18_generator_consumption_once,
        corpus.case19_any_short_circuit_side_effect,
        corpus.case20_bool_operand_return_semantics,
        corpus.case21_chained_comparison_truth,
        corpus.case22_divmod_identity_check,
        corpus.case23_big_integer_precision,
        corpus.case24_bytes_slice_value,
        corpus.case25_bytearray_alias_mutation,
        corpus.case26_tuple_concat_new_object,
        corpus.case27_dict_merge_precedence,
        corpus.case28_try_finally_cleanup_order,
        corpus.case29_exception_handler_specificity,
        corpus.case30_dataclass_default_factory_isolated,
        corpus.case31_sorting_stability,
        corpus.case32_unicode_casefold_equivalence,
        corpus.case33_string_join_generator,
        corpus.case34_partition_semantics,
        corpus.case35_deque_rotate_front,
        corpus.case36_heapq_smallest_after_pushes,
        corpus.case37_groupby_requires_sorted_input,
        corpus.case38_lru_cache_reuses_result,
        corpus.case39_recursion_factorial_small,
        corpus.case40_matrix_alias_pattern,
        corpus.case41_tuple_unpack_swap,
        corpus.case42_list_extend_self_duplicate_length,
        corpus.case43_dict_pop_default_non_mutating,
        corpus.case44_set_intersection_update_result,
        corpus.case45_enumerate_start_offset,
        corpus.case46_zip_truncation_behavior,
        corpus.case47_walrus_assignment_expression,
        corpus.case48_closure_over_mutable_container,
        corpus.case49_nested_comprehension_flatten,
        corpus.case50_reversed_iterator_snapshot,
    ]


def test_case01_late_binding_lambdas() -> None:
    """Verify late-bound loop lambdas all resolve to the final loop value."""
    assert corpus.case01_late_binding_lambdas() == [2, 2, 2]


def test_case02_default_bound_lambdas() -> None:
    """Verify default-arg lambda binding preserves per-iteration values."""
    assert corpus.case02_default_bound_lambdas() == [0, 1, 2]


def test_case03_list_alias_append_len() -> None:
    """Verify list alias append updates original list length."""
    assert corpus.case03_list_alias_append_len() == 1


def test_case04_list_alias_nested_mutation() -> None:
    """Verify nested list alias mutation is visible through original reference."""
    assert corpus.case04_list_alias_nested_mutation() == 7


def test_case05_dict_alias_shared_update() -> None:
    """Verify dict alias update mutates the original dictionary."""
    assert corpus.case05_dict_alias_shared_update() == 9


def test_case06_shallow_copy_shares_nested() -> None:
    """Verify shallow copy shares nested mutable values."""
    assert corpus.case06_shallow_copy_shares_nested() == 2


def test_case07_deep_copy_isolated_nested() -> None:
    """Verify deep copy isolates nested mutable values."""
    assert corpus.case07_deep_copy_isolated_nested() == (1, 2)


def test_case08_mutable_default_persists() -> None:
    """Verify mutable default argument state persists across calls."""
    assert corpus.case08_mutable_default_persists() == (1, 2)


def test_case09_safe_default_isolated() -> None:
    """Verify None-guarded defaults isolate state per call."""
    assert corpus.case09_safe_default_isolated() == (1, 1)


def test_case10_nonlocal_counter_progression() -> None:
    """Verify nonlocal closure state increments across invocations."""
    assert corpus.case10_nonlocal_counter_progression() == (1, 2, 3)


def test_case11_closure_factory_independence() -> None:
    """Verify different closure instances maintain independent state."""
    assert corpus.case11_closure_factory_independence() == (1, 2, 1)


def test_case12_list_slice_assignment() -> None:
    """Verify slice assignment replaces the target range in-place."""
    assert corpus.case12_list_slice_assignment() == [1, 8, 9, 4]


def test_case13_extended_unpacking_middle() -> None:
    """Verify extended unpacking captures middle elements as a list."""
    assert corpus.case13_extended_unpacking_middle() == (1, [2, 3], 4)


def test_case14_negative_index_lookup() -> None:
    """Verify negative indexes resolve from the end of lists."""
    assert corpus.case14_negative_index_lookup() == 30


def test_case15_list_multiply_alias_pitfall() -> None:
    """Verify list multiplication aliases inner mutable containers."""
    assert corpus.case15_list_multiply_alias_pitfall() == (1, 1)


def test_case16_list_comprehension_scope_isolated() -> None:
    """Verify comprehension loop variable does not leak to outer scope."""
    assert corpus.case16_list_comprehension_scope_isolated() is False


def test_case17_setdefault_alias_behavior() -> None:
    """Verify setdefault returns aliased mutable default inserted into dict."""
    assert corpus.case17_setdefault_alias_behavior() == 1


def test_case18_generator_consumption_once() -> None:
    """Verify generators are exhausted after first full consumption."""
    assert corpus.case18_generator_consumption_once() == (6, 0)


def test_case19_any_short_circuit_side_effect() -> None:
    """Verify any() short-circuits after first truthy element."""
    assert corpus.case19_any_short_circuit_side_effect() == 2


def test_case20_bool_operand_return_semantics() -> None:
    """Verify bool operators return original operand objects."""
    assert corpus.case20_bool_operand_return_semantics() == ("right", "fallback")


def test_case21_chained_comparison_truth() -> None:
    """Verify chained comparisons evaluate transitively."""
    assert corpus.case21_chained_comparison_truth() is True


def test_case22_divmod_identity_check() -> None:
    """Verify quotient/remainder reconstruction identity."""
    assert corpus.case22_divmod_identity_check() is True


def test_case23_big_integer_precision() -> None:
    """Verify Python integers preserve arbitrary precision arithmetic."""
    assert corpus.case23_big_integer_precision() == 1


def test_case24_bytes_slice_value() -> None:
    """Verify bytes slicing returns expected byte segment."""
    assert corpus.case24_bytes_slice_value() == b"bcd"


def test_case25_bytearray_alias_mutation() -> None:
    """Verify bytearray alias mutation is visible through all references."""
    assert corpus.case25_bytearray_alias_mutation() == 9


def test_case26_tuple_concat_new_object() -> None:
    """Verify tuple concatenation yields expected immutable tuple value."""
    assert corpus.case26_tuple_concat_new_object() == (1, 2, 3)


def test_case27_dict_merge_precedence() -> None:
    """Verify dictionary merge prioritizes right-hand conflicting keys."""
    assert corpus.case27_dict_merge_precedence() == 9


def test_case28_try_finally_cleanup_order() -> None:
    """Verify return expression value is computed before finally mutation."""
    assert corpus.case28_try_finally_cleanup_order() == "try"


def test_case29_exception_handler_specificity() -> None:
    """Verify specific exception handlers run before generic handlers."""
    assert corpus.case29_exception_handler_specificity() == "key"


def test_case30_dataclass_default_factory_isolated() -> None:
    """Verify dataclass default_factory creates isolated mutable fields."""
    assert corpus.case30_dataclass_default_factory_isolated() == (1, 0)


def test_case31_sorting_stability() -> None:
    """Verify Python sort stability preserves equal-key relative ordering."""
    assert corpus.case31_sorting_stability() == [2, 0, 1]


def test_case32_unicode_casefold_equivalence() -> None:
    """Verify Unicode casefold normalization handles locale-independent matches."""
    assert corpus.case32_unicode_casefold_equivalence() is True


def test_case33_string_join_generator() -> None:
    """Verify string join works with generators of string tokens."""
    assert corpus.case33_string_join_generator() == "0-1-2"


def test_case34_partition_semantics() -> None:
    """Verify partition keeps separator and returns three-part tuple."""
    assert corpus.case34_partition_semantics() == ("a", "=", "b=c")


def test_case35_deque_rotate_front() -> None:
    """Verify deque rotation changes front element as expected."""
    assert corpus.case35_deque_rotate_front() == 3


def test_case36_heapq_smallest_after_pushes() -> None:
    """Verify heap pop returns smallest pushed value."""
    assert corpus.case36_heapq_smallest_after_pushes() == 1


def test_case37_groupby_requires_sorted_input() -> None:
    """Verify groupby groups only adjacent runs of equal keys."""
    assert corpus.case37_groupby_requires_sorted_input() == [("a", 1), ("b", 1), ("a", 2)]


def test_case38_lru_cache_reuses_result() -> None:
    """Verify lru_cache avoids repeated execution for identical arguments."""
    assert corpus.case38_lru_cache_reuses_result() == (28, 1)


def test_case39_recursion_factorial_small() -> None:
    """Verify recursive factorial returns correct value."""
    assert corpus.case39_recursion_factorial_small() == 120


def test_case40_matrix_alias_pattern() -> None:
    """Verify repeated-row matrix pattern aliases inner rows."""
    assert corpus.case40_matrix_alias_pattern() == (3, 3)


def test_case41_tuple_unpack_swap() -> None:
    """Verify tuple unpack assignment swaps values."""
    assert corpus.case41_tuple_unpack_swap() == (2, 1)


def test_case42_list_extend_self_duplicate_length() -> None:
    """Verify extending a list with itself duplicates its contents."""
    assert corpus.case42_list_extend_self_duplicate_length() == 4


def test_case43_dict_pop_default_non_mutating() -> None:
    """Verify pop with default returns fallback without adding new keys."""
    assert corpus.case43_dict_pop_default_non_mutating() == (7, 1)


def test_case44_set_intersection_update_result() -> None:
    """Verify in-place set intersection keeps only shared members."""
    assert corpus.case44_set_intersection_update_result() == {2, 3}


def test_case45_enumerate_start_offset() -> None:
    """Verify enumerate start argument offsets produced indices."""
    assert corpus.case45_enumerate_start_offset() == (5, "x")


def test_case46_zip_truncation_behavior() -> None:
    """Verify zip truncates to shortest iterable length."""
    assert corpus.case46_zip_truncation_behavior() == [(1, 9), (2, 8)]


def test_case47_walrus_assignment_expression() -> None:
    """Verify assignment expressions expose bound value in same scope."""
    assert corpus.case47_walrus_assignment_expression() == 3


def test_case48_closure_over_mutable_container() -> None:
    """Verify closures observe updates to captured mutable containers."""
    assert corpus.case48_closure_over_mutable_container() == (1, 9)


def test_case49_nested_comprehension_flatten() -> None:
    """Verify nested comprehensions flatten nested iterables in row-major order."""
    assert corpus.case49_nested_comprehension_flatten() == [1, 2, 3]


def test_case50_reversed_iterator_snapshot() -> None:
    """Verify reversed iterators yield elements from tail toward head."""
    assert corpus.case50_reversed_iterator_snapshot() == (3, 2)


def test_symbolic_executor_smoke_runs_all_realworld_cases() -> None:
    """Verify symbolic executor can execute every semantics corpus function."""
    executor = _build_executor()
    completed = 0
    for function_object in _all_case_functions():
        _ = executor.execute_function(function_object)
        completed += 1
    assert completed == 50
