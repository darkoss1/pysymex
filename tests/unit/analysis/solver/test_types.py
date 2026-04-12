import pytest
import z3
from pysymex.analysis.solver.types import (
    BugType, Severity, TaintSource, SymType, TaintInfo, SymValue,
    CrashCondition, VerificationResult, FunctionSummary, CallSite, BasicBlock
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

class TestTaintSource:
    """Test suite for pysymex.analysis.solver.types.TaintSource."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert TaintSource.USER_INPUT.value == "user_input"

class TestSymType:
    """Test suite for pysymex.analysis.solver.types.SymType."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert SymType.INT.name == "INT"

class TestTaintInfo:
    """Test suite for pysymex.analysis.solver.types.TaintInfo."""
    def test_source(self) -> None:
        """Test source behavior."""
        info1 = TaintInfo(is_tainted=True, sources={TaintSource.NETWORK})
        assert info1.source == TaintSource.NETWORK
        
        info2 = TaintInfo()
        assert info2.source is None

    def test_propagate(self) -> None:
        """Test propagate behavior."""
        info = TaintInfo(is_tainted=True, sources={TaintSource.USER_INPUT}, propagation_path=["read"])
        prop = info.propagate("eval")
        assert prop.is_tainted is True
        assert "eval" in prop.propagation_path
        
        clean = TaintInfo()
        assert clean.propagate("eval").is_tainted is False

class TestSymValue:
    """Test suite for pysymex.analysis.solver.types.SymValue."""
    def test_is_tainted(self) -> None:
        """Test is_tainted behavior."""
        val1 = SymValue(z3.IntVal(1), taint=TaintInfo(is_tainted=True))
        assert val1.is_tainted is True
        
        val2 = SymValue(z3.IntVal(1))
        assert val2.is_tainted is False

    def test_with_taint(self) -> None:
        """Test with_taint behavior."""
        val = SymValue(z3.IntVal(1), "x", SymType.INT)
        tainted = val.with_taint(TaintSource.USER_INPUT, "input")
        assert tainted.is_tainted is True
        assert tainted.taint.source == TaintSource.USER_INPUT
        assert "input" in tainted.taint.propagation_path

class TestCrashCondition:
    """Test suite for pysymex.analysis.solver.types.CrashCondition."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        crash = CrashCondition(
            BugType.DIVISION_BY_ZERO, z3.BoolVal(True), [], 10, "func", "desc"
        )
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
            "f", "hash", ["x"], [], [], set(), set(), False, False, {}, True
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
