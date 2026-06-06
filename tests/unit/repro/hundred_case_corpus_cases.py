"""Hundred-case symbolic-execution corpus case definitions."""

from __future__ import annotations

from tests.unit.repro.hundred_case_corpus_clean import (
    clean_arithmetic_branch_cases,
    clean_dict_cases,
    clean_fixed_loop_cases,
    clean_guarded_list_cases,
    clean_nonzero_division_cases,
)
from tests.unit.repro.hundred_case_corpus_issues import (
    assertion_issue_cases,
    division_issue_cases,
    key_issue_cases,
    modulo_and_true_division_issue_cases,
    negative_index_issue_cases,
    none_issue_cases,
    positive_index_issue_cases,
    type_issue_cases,
)
from tests.unit.repro.hundred_case_corpus_model import CorpusCase


CASES: list[CorpusCase] = [
    *clean_nonzero_division_cases(),
    *clean_guarded_list_cases(),
    *clean_dict_cases(),
    *clean_arithmetic_branch_cases(),
    *clean_fixed_loop_cases(),
    *division_issue_cases(),
    *modulo_and_true_division_issue_cases(),
    *positive_index_issue_cases(),
    *negative_index_issue_cases(),
    *key_issue_cases(),
    *none_issue_cases(),
    *type_issue_cases(),
    *assertion_issue_cases(),
]

__all__ = ["CASES", "CorpusCase"]
