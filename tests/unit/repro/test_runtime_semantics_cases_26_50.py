"""Tests for real-world Python semantics corpus cases 26 through 50."""

from __future__ import annotations

from tests.repro import runtime_semantics_corpus as corpus


def test_case26_tuple_concat_new_object() -> None:
    assert corpus.case26_tuple_concat_new_object() == (1, 2, 3)


def test_case27_dict_merge_precedence() -> None:
    assert corpus.case27_dict_merge_precedence() == 9


def test_case28_try_finally_cleanup_order() -> None:
    assert corpus.case28_try_finally_cleanup_order() == "try"


def test_case29_exception_handler_specificity() -> None:
    assert corpus.case29_exception_handler_specificity() == "key"


def test_case30_dataclass_default_factory_isolated() -> None:
    assert corpus.case30_dataclass_default_factory_isolated() == (1, 0)


def test_case31_sorting_stability() -> None:
    assert corpus.case31_sorting_stability() == [2, 0, 1]


def test_case32_unicode_casefold_equivalence() -> None:
    assert corpus.case32_unicode_casefold_equivalence() is True


def test_case33_string_join_generator() -> None:
    assert corpus.case33_string_join_generator() == "0-1-2"


def test_case34_partition_semantics() -> None:
    assert corpus.case34_partition_semantics() == ("a", "=", "b=c")


def test_case35_deque_rotate_front() -> None:
    assert corpus.case35_deque_rotate_front() == 3


def test_case36_heapq_smallest_after_pushes() -> None:
    assert corpus.case36_heapq_smallest_after_pushes() == 1


def test_case37_groupby_requires_sorted_input() -> None:
    assert corpus.case37_groupby_requires_sorted_input() == [("a", 1), ("b", 1), ("a", 2)]


def test_case38_lru_cache_reuses_result() -> None:
    assert corpus.case38_lru_cache_reuses_result() == (28, 1)


def test_case39_recursion_factorial_small() -> None:
    assert corpus.case39_recursion_factorial_small() == 120


def test_case40_matrix_alias_pattern() -> None:
    assert corpus.case40_matrix_alias_pattern() == (3, 3)


def test_case41_tuple_unpack_swap() -> None:
    assert corpus.case41_tuple_unpack_swap() == (2, 1)


def test_case42_list_extend_self_duplicate_length() -> None:
    assert corpus.case42_list_extend_self_duplicate_length() == 4


def test_case43_dict_pop_default_non_mutating() -> None:
    assert corpus.case43_dict_pop_default_non_mutating() == (7, 1)


def test_case44_set_intersection_update_result() -> None:
    assert corpus.case44_set_intersection_update_result() == {2, 3}


def test_case45_enumerate_start_offset() -> None:
    assert corpus.case45_enumerate_start_offset() == (5, "x")


def test_case46_zip_truncation_behavior() -> None:
    assert corpus.case46_zip_truncation_behavior() == [(1, 9), (2, 8)]


def test_case47_walrus_assignment_expression() -> None:
    assert corpus.case47_walrus_assignment_expression() == 3


def test_case48_closure_over_mutable_container() -> None:
    assert corpus.case48_closure_over_mutable_container() == (1, 9)


def test_case49_nested_comprehension_flatten() -> None:
    assert corpus.case49_nested_comprehension_flatten() == [1, 2, 3]


def test_case50_reversed_iterator_snapshot() -> None:
    assert corpus.case50_reversed_iterator_snapshot() == (3, 2)
