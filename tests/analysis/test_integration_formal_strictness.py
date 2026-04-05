from __future__ import annotations

from pysymex.analysis.integration.formal import build_done_gate_report
from pysymex.analysis.integration.formal import function_checklist
from pysymex.analysis.integration.formal import run_differential_validation
from pysymex.analysis.integration.formal import run_mutation_robustness


def test_integration_checklist_complete() -> None:
    items = function_checklist()
    assert items
    assert any(i.strict_target for i in items)


def test_integration_differential_passes() -> None:
    stats = run_differential_validation()
    assert stats
    assert all(s.mismatches == 0 for s in stats)


def test_integration_mutation_floor() -> None:
    muts = run_mutation_robustness()
    assert muts
    assert all(m.mutation_score >= 0.66 for m in muts)


def test_integration_done_gate() -> None:
    report = build_done_gate_report()
    assert report["summary"]["done_gate_passed"] is True
