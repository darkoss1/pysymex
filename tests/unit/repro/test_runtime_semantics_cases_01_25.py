"""Tests for real-world Python semantics corpus cases 1 through 25."""

from __future__ import annotations

from tests.repro import runtime_semantics_corpus as corpus


def test_case01_late_binding_lambdas() -> None:
    assert corpus.case01_late_binding_lambdas() == [2, 2, 2]


def test_case02_default_bound_lambdas() -> None:
    assert corpus.case02_default_bound_lambdas() == [0, 1, 2]


def test_case03_list_alias_append_len() -> None:
    assert corpus.case03_list_alias_append_len() == 1


def test_case04_list_alias_nested_mutation() -> None:
    assert corpus.case04_list_alias_nested_mutation() == 7


def test_case05_dict_alias_shared_update() -> None:
    assert corpus.case05_dict_alias_shared_update() == 9


def test_case06_shallow_copy_shares_nested() -> None:
    assert corpus.case06_shallow_copy_shares_nested() == 2


def test_case07_deep_copy_isolated_nested() -> None:
    assert corpus.case07_deep_copy_isolated_nested() == (1, 2)


def test_case08_mutable_default_persists() -> None:
    assert corpus.case08_mutable_default_persists() == (1, 2)


def test_case09_safe_default_isolated() -> None:
    assert corpus.case09_safe_default_isolated() == (1, 1)


def test_case10_nonlocal_counter_progression() -> None:
    assert corpus.case10_nonlocal_counter_progression() == (1, 2, 3)


def test_case11_closure_factory_independence() -> None:
    assert corpus.case11_closure_factory_independence() == (1, 2, 1)


def test_case12_list_slice_assignment() -> None:
    assert corpus.case12_list_slice_assignment() == [1, 8, 9, 4]


def test_case13_extended_unpacking_middle() -> None:
    assert corpus.case13_extended_unpacking_middle() == (1, [2, 3], 4)


def test_case14_negative_index_lookup() -> None:
    assert corpus.case14_negative_index_lookup() == 30


def test_case15_list_multiply_alias_pitfall() -> None:
    assert corpus.case15_list_multiply_alias_pitfall() == (1, 1)


def test_case16_list_comprehension_scope_isolated() -> None:
    assert corpus.case16_list_comprehension_scope_isolated() is False


def test_case17_setdefault_alias_behavior() -> None:
    assert corpus.case17_setdefault_alias_behavior() == 1


def test_case18_generator_consumption_once() -> None:
    assert corpus.case18_generator_consumption_once() == (6, 0)


def test_case19_any_short_circuit_side_effect() -> None:
    assert corpus.case19_any_short_circuit_side_effect() == 2


def test_case20_bool_operand_return_semantics() -> None:
    assert corpus.case20_bool_operand_return_semantics() == ("right", "fallback")


def test_case21_chained_comparison_truth() -> None:
    assert corpus.case21_chained_comparison_truth() is True


def test_case22_divmod_identity_check() -> None:
    assert corpus.case22_divmod_identity_check() is True


def test_case23_big_integer_precision() -> None:
    assert corpus.case23_big_integer_precision() == 1


def test_case24_bytes_slice_value() -> None:
    assert corpus.case24_bytes_slice_value() == b"bcd"


def test_case25_bytearray_alias_mutation() -> None:
    assert corpus.case25_bytearray_alias_mutation() == 9
