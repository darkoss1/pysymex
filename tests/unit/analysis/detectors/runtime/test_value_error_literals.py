"""Tests for ValueError literal and iterable classifiers."""

from __future__ import annotations

import time

import z3

from pysymex.analysis.detectors.runtime.value_error.literals import (
    EmptyIterableCheckStatus,
    is_known_empty_iterable,
    is_known_empty_iterable_result,
)
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.types.containers.lists import SymbolicList


def test_known_empty_iterable_result_reports_concrete_empty() -> None:
    result = is_known_empty_iterable_result([], [])

    assert result.status is EmptyIterableCheckStatus.KNOWN_EMPTY
    assert result.reason == "concrete_empty"
    assert is_known_empty_iterable([], []) is True


def test_known_empty_iterable_result_reports_concrete_non_empty() -> None:
    result = is_known_empty_iterable_result([1], [])

    assert result.status is EmptyIterableCheckStatus.NOT_KNOWN_EMPTY
    assert result.reason == "concrete_non_empty"
    assert is_known_empty_iterable([1], []) is False


def test_known_empty_iterable_result_reports_symbolic_proven_empty() -> None:
    symbolic_list, length_constraint = SymbolicList.symbolic("known_empty_items")

    result = is_known_empty_iterable_result(
        symbolic_list,
        [length_constraint, symbolic_list.z3_len == 0],
    )

    assert result.status is EmptyIterableCheckStatus.KNOWN_EMPTY
    assert result.reason == "non_empty_unsat"


def test_known_empty_iterable_result_reports_feasible_non_empty_case() -> None:
    symbolic_list, length_constraint = SymbolicList.symbolic("possibly_non_empty_items")

    result = is_known_empty_iterable_result(symbolic_list, [length_constraint])

    assert result.status is EmptyIterableCheckStatus.NOT_KNOWN_EMPTY
    assert result.reason == "non_empty_feasible"


def test_known_empty_iterable_result_reports_solver_unknown() -> None:
    symbolic_list, length_constraint = SymbolicList.symbolic("unknown_empty_items")
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        result = is_known_empty_iterable_result(
            symbolic_list,
            [length_constraint, symbolic_list.z3_len == 0],
        )
    finally:
        active_incremental_solver.reset(token)

    assert result.status is EmptyIterableCheckStatus.UNKNOWN
    assert result.reason == "solver_unknown"
    assert is_known_empty_iterable(symbolic_list, [z3.BoolVal(True)]) is False


def test_known_empty_iterable_result_reports_missing_length_model() -> None:
    result = is_known_empty_iterable_result(object(), [])

    assert result.status is EmptyIterableCheckStatus.UNKNOWN
    assert result.reason == "length_unavailable"
