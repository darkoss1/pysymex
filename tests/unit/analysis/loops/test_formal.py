import pytest
from pysymex.analysis.loops.formal import (
    FunctionChecklistItem,
    DifferentialResult,
    MutationResult,
    function_checklist,
    run_differential_validation,
    run_mutation_robustness,
    build_done_gate_report,
)


class TestFunctionChecklistItem:
    """Test suite for pysymex.analysis.loops.formal.FunctionChecklistItem."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        item = FunctionChecklistItem("mod", "qual", True, "status")
        assert item.module == "mod"
        assert item.qualname == "qual"


class TestDifferentialResult:
    """Test suite for pysymex.analysis.loops.formal.DifferentialResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = DifferentialResult("name", 10, 0)
        assert res.samples == 10
        assert res.mismatches == 0


class TestMutationResult:
    """Test suite for pysymex.analysis.loops.formal.MutationResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = MutationResult("name", 10, 8, 0.8)
        assert res.mutation_score == 0.8


def test_function_checklist() -> None:
    """Test function_checklist behavior."""
    items = function_checklist()
    assert len(items) > 0
    assert any(i.module == "core" for i in items)


def test_run_differential_validation() -> None:
    """Test run_differential_validation behavior."""
    res = run_differential_validation()
    assert len(res) == 1
    assert res[0].samples > 0


def test_run_mutation_robustness() -> None:
    """Test run_mutation_robustness behavior."""
    res = run_mutation_robustness()
    assert len(res) == 1
    assert res[0].total_mutants > 0


def test_build_done_gate_report() -> None:
    """Test build_done_gate_report behavior."""
    report = build_done_gate_report()
    assert "function_checklist" in report
    assert "differential_validation" in report
    assert "mutation_robustness" in report
    assert "criteria" in report
