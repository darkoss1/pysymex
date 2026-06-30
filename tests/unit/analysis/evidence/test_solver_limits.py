"""Tests for detector evidence solver resource limits."""

from __future__ import annotations

import time
from typing import Never

import pytest
import z3

from pysymex._internal.analysis.detectors.feasibility import detector_witness_model
from pysymex._internal.analysis.evidence.solvers import create_evidence_solver
from pysymex._internal.analysis.evidence.witness.models import substitution_model
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver


def test_create_evidence_solver_returns_none_after_active_deadline() -> None:
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = SolverContext.active.set(solver)
    try:
        evidence_solver = create_evidence_solver()
    finally:
        SolverContext.active.reset(token)

    assert evidence_solver is None


def test_create_evidence_solver_returns_none_for_tiny_active_budget() -> None:
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() + 0.05)
    token = SolverContext.active.set(solver)
    try:
        evidence_solver = create_evidence_solver()
    finally:
        SolverContext.active.reset(token)

    assert evidence_solver is None


def test_substitution_model_skips_raw_solver_after_active_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    x = z3.Int("expired_witness_x")
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)

    def fail_solver_construction() -> Never:
        raise AssertionError("expired evidence query must not construct a raw Z3 solver")

    monkeypatch.setattr(z3, "Solver", fail_solver_construction)
    token = SolverContext.active.set(solver)
    try:
        model = substitution_model([(x, z3.IntVal(1))])
    finally:
        SolverContext.active.reset(token)

    assert model is None


def test_detector_witness_model_skips_simplify_for_tiny_active_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    x = z3.Int("tiny_budget_witness_x")
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() + 0.05)

    def fail_simplify(*_args: object, **_kwargs: object) -> Never:
        raise AssertionError("tiny-budget evidence query must not simplify detector formulas")

    monkeypatch.setattr(z3, "simplify", fail_simplify)
    token = SolverContext.active.set(solver)
    try:
        model = detector_witness_model([x == 1])
    finally:
        SolverContext.active.reset(token)

    assert model is None


def test_detector_witness_model_uses_short_solver_timeout_with_ample_deadline() -> None:
    a = z3.Int("short_budget_detector_witness_a")
    b = z3.Int("short_budget_detector_witness_b")
    c = z3.Int("short_budget_detector_witness_c")
    any_result = z3.Bool("short_budget_detector_witness_any")
    xor_parity = (z3.Int2BV(a, 64) ^ z3.Int2BV(b, 64) ^ z3.Int2BV(c, 64)) & z3.BitVecVal(1, 64)
    constraints = [
        xor_parity == z3.BitVecVal(1, 64),
        any_result
        == z3.Or(
            a - b == 0,
            b - c == 0,
            c - a == 0,
        ),
        any_result,
        a == b,
        c % 2 == 1,
        a - b == 0,
    ]
    solver = IncrementalSolver(timeout_ms=100)
    solver.set_deadline(time.perf_counter() + 10.0)
    token = SolverContext.active.set(solver)
    try:
        model = detector_witness_model(constraints)
    finally:
        SolverContext.active.reset(token)

    assert model is not None
    assert z3.is_true(model.eval(z3.And(*constraints), model_completion=True))
