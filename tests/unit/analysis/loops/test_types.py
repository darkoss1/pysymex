import z3
from pysymex.analysis.loops.types import (
    LoopType,
    LoopBound,
    LoopInfo,
    InductionVariable,
    LoopSummary,
)


class TestLoopType:
    """Test suite for pysymex.analysis.loops.types.LoopType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert LoopType.FOR_RANGE.name == "FOR_RANGE"


class TestLoopBound:
    """Test suite for pysymex.analysis.loops.types.LoopBound."""

    def test_constant(self) -> None:
        """Test constant behavior."""
        b = LoopBound.constant(5)
        assert b.is_finite is True
        assert b.upper == 5

    def test_range(self) -> None:
        """Test range behavior."""
        b = LoopBound.range(1, 10)
        assert b.lower == 1
        assert b.upper == 10

    def test_unbounded(self) -> None:
        """Test unbounded behavior."""
        b = LoopBound.unbounded()
        assert b.is_finite is False

    def test_symbolic(self) -> None:
        """Test symbolic behavior."""
        x = z3.Int("x")
        b = LoopBound.symbolic(x)
        assert b.upper is x
        assert b.exact is x


class TestLoopInfo:
    """Test suite for pysymex.analysis.loops.types.LoopInfo."""

    def test_contains_pc(self) -> None:
        """Test contains_pc behavior."""
        info = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 15, 20})
        assert info.contains_pc(10) is True
        assert info.contains_pc(15) is True
        assert info.contains_pc(99) is False

    def test_is_header(self) -> None:
        """Test is_header behavior."""
        info = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 15, 20})
        assert info.is_header(10) is True
        assert info.is_header(15) is False

    def test_is_exit(self) -> None:
        """Test is_exit behavior."""
        info = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 15, 20})
        assert info.is_exit(30) is True
        assert info.is_exit(20) is False


class TestInductionVariable:
    """Test suite for pysymex.analysis.loops.types.InductionVariable."""

    def test_value_at_iteration(self) -> None:
        """Test value_at_iteration behavior."""
        iv = InductionVariable("i", z3.IntVal(0), z3.IntVal(1))
        val = iv.value_at_iteration(z3.IntVal(5))
        # Check that the expression is correct by simplifying
        assert str(val) == "0 + 1*5"

    def test_final_value(self) -> None:
        """Test final_value behavior."""
        iv = InductionVariable("i", z3.IntVal(0), z3.IntVal(2))
        val = iv.final_value(z3.IntVal(3))
        # Check that the expression is correct by simplifying
        assert str(val) == "0 + 2*3"


class TestLoopSummary:
    """Test suite for pysymex.analysis.loops.types.LoopSummary."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        summary = LoopSummary(
            iterations=10, variable_effects={"x": z3.IntVal(5)}, memory_effects={}
        )
        assert summary.iterations == 10
        assert "x" in summary.variable_effects
