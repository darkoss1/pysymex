from unittest.mock import patch, Mock
import z3
from pysymex.analysis.detectors.formal import (
    DetectorFormalSpec,
    ProofObligationResult,
    StatisticalResult,
    MutationResult,
    OracleResult,
    specs,
    prove_smt_obligations,
    run_property_validation,
    run_mutation_analysis,
    run_oracle_differential_validation,
    build_machine_checkable_report,
)


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


class TestMutationResult:
    """Test suite for pysymex.analysis.detectors.formal.MutationResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = MutationResult("det", 10, 8, 0.8)
        assert res.mutation_score == 0.8


class TestOracleResult:
    """Test suite for pysymex.analysis.detectors.formal.OracleResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = OracleResult("det", 100, 2, 0.02, 0.05)
        assert res.mismatches == 2


def test_specs() -> None:
    """Test specs behavior."""
    s = specs()
    assert len(s) > 0
    assert any(x.detector == "division-by-zero" for x in s)


@patch("pysymex.analysis.detectors.formal.is_satisfiable", return_value=False)
def test_prove_smt_obligations(mock_is_sat) -> None:
    """Test prove_smt_obligations behavior."""
    results = prove_smt_obligations()
    assert len(results) > 0
    assert all(r.passed is True for r in results)


@patch("pysymex.analysis.detectors.formal.pure_check_division_by_zero", return_value=None)
@patch("pysymex.analysis.detectors.formal.pure_check_index_bounds", return_value=None)
@patch("pysymex.analysis.detectors.formal.pure_check_none_deref", return_value=None)
@patch("pysymex.analysis.detectors.formal.is_satisfiable", return_value=True)
def test_run_property_validation(m1, m2, m3, m4) -> None:
    """Test run_property_validation behavior."""
    with (
        patch("pysymex.analysis.detectors.formal.SymbolicValue.symbolic") as m_sym,
        patch("pysymex.analysis.detectors.formal.SymbolicList.symbolic") as m_list,
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

        res = run_property_validation(samples=2, seed=42)
        assert len(res) == 4
        assert res[0].samples == 2


@patch("pysymex.analysis.detectors.formal.is_satisfiable", return_value=True)
def test_run_mutation_analysis(mock_is_sat) -> None:
    """Test run_mutation_analysis behavior."""
    res = run_mutation_analysis()
    assert len(res) == 4
    assert res[0].total_mutants > 0


@patch("pysymex.analysis.detectors.formal.pure_check_division_by_zero", return_value=None)
@patch("pysymex.analysis.detectors.formal.pure_check_index_bounds", return_value=None)
@patch("pysymex.analysis.detectors.formal.pure_check_none_deref", return_value=None)
def test_run_oracle_differential_validation(m1, m2, m3) -> None:
    """Test run_oracle_differential_validation behavior."""
    with (
        patch("pysymex.analysis.detectors.formal.SymbolicValue.symbolic") as m_sym,
        patch("pysymex.analysis.detectors.formal.SymbolicList.symbolic") as m_list,
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


@patch("pysymex.analysis.detectors.formal.run_property_validation", return_value=[])
@patch(
    "pysymex.analysis.detectors.formal.run_mutation_analysis",
    return_value=[MutationResult("foo", 1, 1, 1.0)],
)
@patch("pysymex.analysis.detectors.formal.run_oracle_differential_validation", return_value=[])
@patch("pysymex.analysis.detectors.formal.prove_smt_obligations", return_value=[])
def test_build_machine_checkable_report(m1, m2, m3, m4) -> None:
    """Test build_machine_checkable_report behavior."""
    report = build_machine_checkable_report(samples=2, seed=42)
    assert "specs" in report
    assert "summary" in report
