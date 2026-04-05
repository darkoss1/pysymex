from __future__ import annotations

from pysymex.analysis.solver.formal import build_done_gate_report
from pysymex.analysis.solver.formal import function_checklist
from pysymex.analysis.solver.formal import run_mutation_robustness
from pysymex.analysis.solver.formal import run_opcode_differential_validation


def test_solver_function_checklist_is_complete() -> None:
    items = function_checklist()
    assert items
    assert any(i.strict_target for i in items)
    assert all(i.status in {"strict-tested", "inventory-reviewed"} for i in items)


def test_solver_differential_validation_is_strict() -> None:
    stats = run_opcode_differential_validation(samples=260, seed=17)
    assert stats
    for st in stats:
        assert st.mismatch_upper_95 <= 0.05


def test_solver_mutation_robustness_strong() -> None:
    muts = run_mutation_robustness()
    assert muts
    for m in muts:
        assert m.mutation_score >= 0.66


def test_solver_done_gate_report_passes() -> None:
    report = build_done_gate_report(samples=240, seed=31)
    assert "function_checklist" in report
    assert "differential_validation" in report
    assert "mutation_robustness" in report
    assert "criteria" in report
    assert "summary" in report
    assert report["summary"]["done_gate_passed"] is True
