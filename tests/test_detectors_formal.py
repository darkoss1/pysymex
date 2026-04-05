from __future__ import annotations

from pysymex.analysis.detectors.formal import (
    build_machine_checkable_report,
    prove_smt_obligations,
    run_mutation_analysis,
    run_oracle_differential_validation,
    run_property_validation,
)


def test_smt_obligations_all_pass() -> None:
    obligations = prove_smt_obligations()
    assert obligations
    assert all(o.passed for o in obligations)


def test_property_validation_low_error_bounds() -> None:
    stats = run_property_validation(samples=300, seed=1)
    assert stats
    for st in stats:
        assert st.fp_upper_95 <= 0.05
        assert st.fn_upper_95 <= 0.05


def test_mutation_score_strong() -> None:
    muts = run_mutation_analysis()
    assert muts
    for m in muts:
        assert m.mutation_score >= 0.66


def test_oracle_differential_validation_is_strict() -> None:
    stats = run_oracle_differential_validation(samples=220, seed=19)
    assert stats
    for st in stats:
        assert st.mismatch_upper_95 <= 0.05


def test_report_is_machine_checkable() -> None:
    report = build_machine_checkable_report(samples=120, seed=3)
    assert "specs" in report
    assert "proof_obligations" in report
    assert "property_validation" in report
    assert "mutation_analysis" in report
    assert "oracle_differential_validation" in report
    assert "summary" in report
