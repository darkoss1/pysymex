from __future__ import annotations

from pysymex.analysis.resources.formal import build_done_gate_report
from pysymex.analysis.resources.formal import function_checklist
from pysymex.analysis.resources.formal import run_differential_validation
from pysymex.analysis.resources.formal import run_mutation_robustness


def test_resources_checklist_is_complete() -> None:
    items = function_checklist()
    assert items
    assert any(i.strict_target for i in items)


def test_resources_differential_validation_strict() -> None:
    stats = run_differential_validation()
    assert stats
    for st in stats:
        assert st.mismatches == 0


def test_resources_mutation_robustness() -> None:
    muts = run_mutation_robustness()
    assert muts
    for m in muts:
        assert m.mutation_score >= 0.66


def test_resources_done_gate_report_passes() -> None:
    report = build_done_gate_report()
    assert "function_checklist" in report
    assert "differential_validation" in report
    assert "mutation_robustness" in report
    assert "criteria" in report
    assert "summary" in report
    assert report["summary"]["done_gate_passed"] is True
