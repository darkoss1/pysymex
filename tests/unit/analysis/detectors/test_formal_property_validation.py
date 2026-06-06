import time
from unittest.mock import MagicMock, Mock, patch

import z3

from pysymex.analysis.detectors.formal import run_property_validation
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult
from pysymex.utils.math import wilson_upper_95


@patch(
    "pysymex.analysis.detectors.formal.property_validation.pure_check_division_by_zero",
    return_value=None,
)
@patch(
    "pysymex.analysis.detectors.formal.property_validation.pure_check_index_bounds",
    return_value=None,
)
@patch(
    "pysymex.analysis.detectors.formal.property_validation.pure_check_none_deref",
    return_value=None,
)
@patch(
    "pysymex.analysis.detectors.formal.property_validation._sat_status",
    return_value=SolverResult.sat(None),
)
def test_run_property_validation(
    _m1: MagicMock, _m2: MagicMock, _m3: MagicMock, _m4: MagicMock
) -> None:
    """Test run_property_validation behavior."""
    with (
        patch(
            "pysymex.analysis.detectors.formal.property_validation.SymbolicValue.symbolic"
        ) as m_sym,
        patch(
            "pysymex.analysis.detectors.formal.property_validation.SymbolicList.symbolic"
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

        res = run_property_validation(samples=2, seed=42)
        assert len(res) == 4
        assert res[0].samples == 2
        assert all(result.inconclusive_samples == 0 for result in res)


def test_run_property_validation_rates_use_conclusive_samples() -> None:
    """Skipped UNKNOWN samples must not dilute property-validation rates."""
    case_results = [
        (True, False, False),
        (False, True, False),
        (False, False, True),
    ]

    with (
        patch(
            "pysymex.analysis.detectors.formal.property_validation._division_case",
            side_effect=case_results.copy(),
        ),
        patch(
            "pysymex.analysis.detectors.formal.property_validation._index_case",
            side_effect=case_results.copy(),
        ),
        patch(
            "pysymex.analysis.detectors.formal.property_validation._none_case",
            side_effect=case_results.copy(),
        ),
        patch(
            "pysymex.analysis.detectors.formal.property_validation._key_case",
            side_effect=case_results.copy(),
        ),
    ):
        results = run_property_validation(samples=3, seed=42)

    assert len(results) == 4
    assert all(result.inconclusive_samples == 1 for result in results)
    assert all(result.fp_rate == 0.5 for result in results)
    assert all(result.fn_rate == 0.5 for result in results)
    assert all(result.fp_upper_95 == wilson_upper_95(1, 2) for result in results)
    assert all(result.fn_upper_95 == wilson_upper_95(1, 2) for result in results)


def test_run_property_validation_preserves_solver_unknown_status() -> None:
    """Solver UNKNOWN samples must not become false positives or negatives."""
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        results = run_property_validation(samples=2, seed=42)
    finally:
        active_incremental_solver.reset(token)

    assert len(results) == 4
    assert all(result.false_positives == 0 for result in results)
    assert all(result.false_negatives == 0 for result in results)
    assert any(result.inconclusive_samples > 0 for result in results)
