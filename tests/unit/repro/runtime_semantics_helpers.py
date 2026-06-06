"""Shared helpers for runtime semantics corpus unit tests."""

from __future__ import annotations

from collections.abc import Callable

from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.config.settings import ExecutionConfig
from tests.repro import runtime_semantics_corpus as corpus


def build_executor() -> SymbolicExecutor:
    """Create a deterministic executor configuration for corpus smoke checks."""
    config = ExecutionConfig(
        max_paths=128,
        max_depth=128,
        max_iterations=8192,
        timeout_seconds=20.0,
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


def all_case_functions() -> list[Callable[[], object]]:
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
