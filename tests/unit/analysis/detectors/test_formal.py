import time
from unittest.mock import MagicMock, Mock, patch

import z3

from pysymex.analysis.detectors.formal import (
    build_machine_checkable_report,
    prove_smt_obligations,
    run_mutation_analysis,
    run_oracle_differential_validation,
    specs,
)
from pysymex.analysis.detectors.formal.types import (
    DetectorFormalSpec,
    MutationResult,
    OracleResult,
    ProofObligationResult,
    StatisticalResult,
)
from pysymex.analysis.detectors.formal import oracle_validation
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.utils.math import wilson_upper_95


class TestDetectorFormalSpec:
    """Test suite for pysymex.analysis.detectors.formal.DetectorFormalSpec."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        spec = DetectorFormalSpec("det", "risk", "claim", 0.05)
        assert spec.detector == "det"
        assert spec.risk_formula == "risk"


class TestProofObligationResult:
    """Test suite for pysymex.analysis.detectors.formal.ProofObligationResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = ProofObligationResult("det", "obl", True, "status")
        assert res.passed is True


class TestStatisticalResult:
    """Test suite for pysymex.analysis.detectors.formal.StatisticalResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = StatisticalResult("det", 100, 5, 5, 0.05, 0.05, 0.1, 0.1)
        assert res.samples == 100
        assert res.inconclusive_samples == 0


class TestMutationResult:
    """Test suite for pysymex.analysis.detectors.formal.MutationResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = MutationResult("det", 10, 8, 0.8)
        assert res.mutation_score == 0.8
        assert res.inconclusive_mutants == 0


class TestOracleResult:
    """Test suite for pysymex.analysis.detectors.formal.OracleResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = OracleResult("det", 100, 2, 0.02, 0.05)
        assert res.mismatches == 2
        assert res.inconclusive_samples == 0


def test_specs() -> None:
    """Test specs behavior."""
    s = specs()
    assert len(s) > 0
    assert any(x.detector == "division-by-zero" for x in s)


def test_prove_smt_obligations() -> None:
    """Test prove_smt_obligations behavior."""
    results = prove_smt_obligations()
    assert len(results) > 0
    assert all(r.passed is True for r in results)
    assert {r.status for r in results} == {"unsat"}


def test_prove_smt_obligations_preserves_solver_unknown_status() -> None:
    """Solver UNKNOWN must not be labeled as a proved UNSAT obligation."""
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        results = prove_smt_obligations()
    finally:
        active_incremental_solver.reset(token)

    assert len(results) > 0
    assert all(r.passed is False for r in results)
    assert {r.status for r in results} == {"unknown"}


@patch("pysymex.analysis.detectors.formal.mutation._sat_status")
def test_run_mutation_analysis(mock_sat_status: MagicMock) -> None:
    """Test run_mutation_analysis behavior."""
    mock_sat_status.return_value = IncrementalSolver().check_sat_result([z3.BoolVal(True)])
    res = run_mutation_analysis()
    assert len(res) == 4
    assert res[0].total_mutants > 0
    assert res[0].inconclusive_mutants == 0


def test_run_mutation_analysis_preserves_solver_unknown_status() -> None:
    """Solver UNKNOWN must be counted as inconclusive mutation evidence."""
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        results = run_mutation_analysis()
    finally:
        active_incremental_solver.reset(token)

    assert len(results) == 4
    assert all(result.killed_mutants == 0 for result in results)
    assert all(result.inconclusive_mutants == result.total_mutants for result in results)


@patch(
    "pysymex.analysis.detectors.formal.oracle_validation.pure_check_division_by_zero",
    return_value=None,
)
@patch(
    "pysymex.analysis.detectors.formal.oracle_validation.pure_check_index_bounds", return_value=None
)
@patch(
    "pysymex.analysis.detectors.formal.oracle_validation.pure_check_none_deref", return_value=None
)
def test_run_oracle_differential_validation(_m1: MagicMock, _m2: MagicMock, _m3: MagicMock) -> None:
    """Test run_oracle_differential_validation behavior."""
    with (
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.SymbolicValue.symbolic"
        ) as m_sym,
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.SymbolicList.symbolic"
        ) as m_list,
    ):
        m_mock = Mock()
        m_mock.is_int = z3.Bool("m_is_int")
        m_mock.is_float = z3.Bool("m_is_float")
        m_mock.z3_int = z3.Int("m_z3_int")
        m_mock.z3_float = z3.FP("m_z3_float", z3.Float64())
        m_mock.is_none = z3.Bool("m_is_none")
        m_sym.return_value = (m_mock, z3.BoolVal(True))

        m_list_mock = Mock()
        m_list_mock.z3_len = z3.Int("m_z3_len")
        m_list.return_value = (m_list_mock, z3.BoolVal(True))

        res = run_oracle_differential_validation(samples=2, seed=42)
        assert len(res) == 4
        assert res[0].samples == 2


def test_run_oracle_differential_validation_preserves_solver_unknown_status() -> None:
    """Solver UNKNOWN oracle samples must not become detector mismatches."""
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        results = run_oracle_differential_validation(samples=2, seed=42)
    finally:
        active_incremental_solver.reset(token)

    assert len(results) == 4
    assert all(result.mismatches == 0 for result in results)
    assert any(result.inconclusive_samples > 0 for result in results)


def test_run_oracle_differential_validation_rates_use_conclusive_samples() -> None:
    """Skipped UNKNOWN samples must not dilute oracle mismatch rates."""
    with (
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation._sat_status",
            side_effect=[
                SolverResult.unknown(),
                SolverResult.sat(None),
                SolverResult.sat(None),
                SolverResult.sat(None),
            ],
        ),
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.pure_check_division_by_zero",
            return_value=None,
        ),
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.pure_check_index_bounds",
            return_value=None,
        ),
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.pure_check_none_deref",
            return_value=None,
        ),
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.oracle_division_risk",
            return_value=True,
        ),
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.oracle_index_risk",
            return_value=False,
        ),
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.oracle_none_risk",
            return_value=False,
        ),
        patch(
            "pysymex.analysis.detectors.formal.oracle_validation.oracle_key_risk",
            return_value=False,
        ),
        patch.object(oracle_validation.KeyErrorDetector, "check", return_value=None),
    ):
        results = run_oracle_differential_validation(samples=2, seed=42)

    division = next(result for result in results if result.detector == "division-by-zero")
    assert division.inconclusive_samples == 1
    assert division.mismatches == 1
    assert division.mismatch_rate == 1.0
    assert division.mismatch_upper_95 == wilson_upper_95(1, 1)


@patch("pysymex.analysis.detectors.formal.run_property_validation", return_value=[])
@patch(
    "pysymex.analysis.detectors.formal.run_mutation_analysis",
    return_value=[MutationResult("foo", 1, 1, 1.0)],
)
@patch("pysymex.analysis.detectors.formal.run_oracle_differential_validation", return_value=[])
@patch("pysymex.analysis.detectors.formal.prove_smt_obligations", return_value=[])
def test_build_machine_checkable_report(
    _m1: MagicMock, _m2: MagicMock, _m3: MagicMock, _m4: MagicMock
) -> None:
    """Test build_machine_checkable_report behavior."""
    report = build_machine_checkable_report(samples=2, seed=42)
    assert "specs" in report
    assert "summary" in report
    summary = report["summary"]
    assert isinstance(summary, dict)
    assert summary["mutation_analysis_inconclusive_mutants"] == 0
    assert summary["property_validation_inconclusive_samples"] == 0
    assert summary["oracle_differential_inconclusive_samples"] == 0


@patch(
    "pysymex.analysis.detectors.formal.run_property_validation",
    return_value=[
        StatisticalResult(
            detector="division-by-zero",
            samples=10,
            false_positives=0,
            false_negatives=0,
            fp_rate=0.0,
            fn_rate=0.0,
            fp_upper_95=0.0,
            fn_upper_95=0.0,
            inconclusive_samples=10,
        )
    ],
)
@patch(
    "pysymex.analysis.detectors.formal.run_mutation_analysis",
    return_value=[MutationResult("foo", 1, 1, 1.0)],
)
@patch(
    "pysymex.analysis.detectors.formal.run_oracle_differential_validation",
    return_value=[
        OracleResult(
            detector="division-by-zero",
            samples=10,
            mismatches=0,
            mismatch_rate=0.0,
            mismatch_upper_95=0.0,
            inconclusive_samples=10,
        )
    ],
)
@patch("pysymex.analysis.detectors.formal.prove_smt_obligations", return_value=[])
def test_build_machine_checkable_report_does_not_mark_inconclusive_metrics_as_clean(
    _m1: MagicMock, _m2: MagicMock, _m3: MagicMock, _m4: MagicMock
) -> None:
    """Summary success lists must require conclusive validation samples."""
    report = build_machine_checkable_report(samples=10, seed=42)
    summary = report["summary"]

    assert isinstance(summary, dict)
    assert summary["detectors_within_fp_target"] == []
    assert summary["oracle_mismatch_free"] == []
    assert summary["property_validation_inconclusive_samples"] == 10
    assert summary["oracle_differential_inconclusive_samples"] == 10
