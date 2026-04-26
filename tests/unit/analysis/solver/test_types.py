import pytest
import z3
from pysymex.analysis.solver.types import (
    BugType,
    Severity,
    SymType,
    CrashCondition,
    VerificationResult,
    FunctionSummary,
    CallSite,
    BasicBlock,
)


class TestBugType:
    """Test suite for pysymex.analysis.solver.types.BugType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert BugType.DIVISION_BY_ZERO.value == "division_by_zero"


class TestSeverity:
    """Test suite for pysymex.analysis.solver.types.Severity."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert Severity.CRITICAL.value == 1


class TestSymType:
    """Test suite for pysymex.analysis.solver.types.SymType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert SymType.INT.name == "INT"


class TestSymValue:
    """Test suite for pysymex.analysis.solver.types.SymValue."""


class TestCrashCondition:
    """Test suite for pysymex.analysis.solver.types.CrashCondition."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        crash = CrashCondition(BugType.DIVISION_BY_ZERO, z3.BoolVal(True), [], 10, "func", "desc")
        assert crash.bug_type == BugType.DIVISION_BY_ZERO
        assert crash.line == 10


class TestVerificationResult:
    """Test suite for pysymex.analysis.solver.types.VerificationResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        crash = CrashCondition(BugType.DIVISION_BY_ZERO, z3.BoolVal(True), [], 10, "func", "desc")
        res = VerificationResult(crash, True, False)
        assert res.can_crash is True
        assert res.proven_safe is False


class TestFunctionSummary:
    """Test suite for pysymex.analysis.solver.types.FunctionSummary."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        summary = FunctionSummary(
            "f", "hash", ["x"], [], [], set(), set(), False, False, True, True, False
        )
        assert summary.name == "f"
        assert summary.pure is True


class TestCallSite:
    """Test suite for pysymex.analysis.solver.types.CallSite."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        site = CallSite("caller", "callee", 10, ["x"])
        assert site.caller == "caller"
        assert site.line == 10


class TestBasicBlock:
    """Test suite for pysymex.analysis.solver.types.BasicBlock."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        b = BasicBlock(1)
        assert b.id == 1
        assert b.reachable is True
