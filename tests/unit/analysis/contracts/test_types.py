import pytest
import z3
from pysymex.analysis.contracts.types import (
    ContractKind, VerificationResult, ContractViolation, Contract, FunctionContract
)

class TestContractKind:
    """Test suite for pysymex.analysis.contracts.types.ContractKind."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ContractKind.REQUIRES.name == "REQUIRES"
        assert ContractKind.ENSURES.name == "ENSURES"

class TestVerificationResult:
    """Test suite for pysymex.analysis.contracts.types.VerificationResult."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert VerificationResult.VERIFIED.name == "VERIFIED"
        assert VerificationResult.VIOLATED.name == "VIOLATED"

class TestContractViolation:
    """Test suite for pysymex.analysis.contracts.types.ContractViolation."""
    def test_format(self) -> None:
        """Test format behavior."""
        v = ContractViolation(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
            message="Must be positive",
            line_number=10,
            function_name="foo",
            counterexample={"x": -1}
        )
        fmt = v.format()
        assert "[REQUIRES] in foo at line 10: Must be positive" in fmt
        assert "Condition: x > 0" in fmt
        assert "x = -1" in fmt

class TestContract:
    """Test suite for pysymex.analysis.contracts.types.Contract."""
    def test_compile(self) -> None:
        """Test compile behavior."""
        c = Contract(
            kind=ContractKind.REQUIRES,
            condition="x > 0",
            message="msg",
        )
        syms = {"x": z3.Int("x")}
        expr = c.compile(syms)
        # Check that expr is a valid z3 boolean reference
        assert isinstance(expr, z3.BoolRef)

class TestFunctionContract:
    """Test suite for pysymex.analysis.contracts.types.FunctionContract."""
    def test_add_precondition(self) -> None:
        """Test add_precondition behavior."""
        fc = FunctionContract("my_func")
        fc.add_precondition("x > 0", "msg", 5)
        assert len(fc.preconditions) == 1
        assert fc.preconditions[0].condition == "x > 0"
        assert fc.preconditions[0].line_number == 5

    def test_add_postcondition(self) -> None:
        """Test add_postcondition behavior."""
        fc = FunctionContract("my_func")
        fc.add_postcondition("result() == 1", "msg", 10)
        assert len(fc.postconditions) == 1
        assert fc.postconditions[0].condition == "result() == 1"
        assert fc.postconditions[0].line_number == 10

    def test_add_loop_invariant(self) -> None:
        """Test add_loop_invariant behavior."""
        fc = FunctionContract("my_func")
        fc.add_loop_invariant(20, "i < n", "msg", 15)
        assert 20 in fc.loop_invariants
        assert len(fc.loop_invariants[20]) == 1
        assert fc.loop_invariants[20][0].condition == "i < n"
        assert fc.loop_invariants[20][0].line_number == 15
