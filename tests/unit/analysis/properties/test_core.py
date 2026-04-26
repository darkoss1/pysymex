import pytest
import z3
from pysymex.analysis.properties.core import PropertyProver, ArithmeticVerifier, EquivalenceChecker
from pysymex.analysis.properties.types import PropertyKind


class TestPropertyProver:
    """Test suite for pysymex.analysis.properties.core.PropertyProver."""

    def test_prove_commutativity(self) -> None:
        """Test prove_commutativity behavior."""
        p = PropertyProver()
        res = p.prove_commutativity(lambda x, y: x + y, z3.Int("a"), z3.Int("b"))
        assert res.is_proven is True

    def test_prove_associativity(self) -> None:
        """Test prove_associativity behavior."""
        p = PropertyProver()
        res = p.prove_associativity(lambda x, y: x + y, z3.Int("a"), z3.Int("b"), z3.Int("c"))
        assert res.is_proven is True

    def test_prove_identity(self) -> None:
        """Test prove_identity behavior."""
        p = PropertyProver()
        res = p.prove_identity(lambda x, y: x + y, z3.Int("a"), z3.IntVal(0))
        assert res.is_proven is True

    def test_prove_idempotence(self) -> None:
        """Test prove_idempotence behavior."""
        p = PropertyProver()

        def op(x, y):
            return x

        res = p.prove_idempotence(lambda x, y: x, z3.Int("a"))
        assert res.is_proven is True

    def test_prove_monotonic_increasing(self) -> None:
        """Test prove_monotonic_increasing behavior."""
        p = PropertyProver()

        def f(x):
            return x + 1

        res = p.prove_monotonic_increasing(f, z3.Int("x"), z3.Int("y"))
        assert res.is_proven is True

    def test_prove_monotonic_decreasing(self) -> None:
        """Test prove_monotonic_decreasing behavior."""
        p = PropertyProver()

        def f(x):
            return -x

        res = p.prove_monotonic_decreasing(f, z3.Int("x"), z3.Int("y"))
        assert res.is_proven is True

    def test_prove_lower_bound(self) -> None:
        """Test prove_lower_bound behavior."""
        p = PropertyProver()
        x = z3.Int("x")

        def f(x):
            return z3.If(x < 0, z3.IntVal(0), x)

        res = p.prove_lower_bound(f(x), z3.IntVal(0), {"x": x})
        assert res.is_proven is True

    def test_prove_upper_bound(self) -> None:
        """Test prove_upper_bound behavior."""
        p = PropertyProver()
        x = z3.Int("x")

        def f(x):
            return z3.If(x > 10, z3.IntVal(10), x)

        res = p.prove_upper_bound(f(x), z3.IntVal(10), {"x": x})
        assert res.is_proven is True

    def test_prove_bounded(self) -> None:
        """Test prove_bounded behavior."""
        p = PropertyProver()
        x = z3.Int("x")

        def f(x):
            return z3.If(x < 0, z3.IntVal(0), z3.If(x > 10, z3.IntVal(10), x))

        res = p.prove_bounded(f(x), z3.IntVal(0), z3.IntVal(10), {"x": x})
        assert res.is_proven is True

    def test_prove_non_negative(self) -> None:
        """Test prove_non_negative behavior."""
        p = PropertyProver()
        x = z3.Int("x")

        def f(x):
            return x * x

        res = p.prove_non_negative(f(x), {"x": x})
        assert res.is_proven is True

    def test_prove_positive(self) -> None:
        """Test prove_positive behavior."""
        p = PropertyProver()
        x = z3.Int("x")

        def f(x):
            return x * x + 1

        res = p.prove_positive(f(x), {"x": x})
        assert res.is_proven is True

    def test_prove_equivalence(self) -> None:
        """Test prove_equivalence behavior."""
        p = PropertyProver()
        x = z3.Int("x")
        res = p.prove_equivalence(x + x, 2 * x, {"x": x})
        assert res.is_proven is True

    def test_prove_even_function(self) -> None:
        """Test prove_even_function behavior."""
        p = PropertyProver()
        res = p.prove_even_function(lambda x: x * x, z3.Int("x"))
        assert res.is_proven is True

    def test_prove_odd_function(self) -> None:
        """Test prove_odd_function behavior."""
        p = PropertyProver()
        res = p.prove_odd_function(lambda x: x * x * x, z3.Int("x"))
        assert res.is_proven is True

    def test_prove_injective(self) -> None:
        """Test prove_injective behavior."""
        p = PropertyProver()
        res = p.prove_injective(lambda x: x + 1, z3.Int("x"), z3.Int("y"))
        assert res.is_proven is True

    def test_prove_custom(self) -> None:
        """Test prove_custom behavior."""
        p = PropertyProver()
        res = p.prove_custom("prop", z3.BoolVal(True), {})
        assert res.is_proven is True


class TestArithmeticVerifier:
    """Test suite for pysymex.analysis.properties.core.ArithmeticVerifier."""

    def test_check_overflow(self) -> None:
        """Test check_overflow behavior."""
        v = ArithmeticVerifier()
        x = z3.Int("x")
        y = z3.Int("y")
        expr = x + y
        res = v.check_overflow(expr, {"x": x, "y": y})
        assert res.is_disproven is True

    def test_check_underflow(self) -> None:
        """Test check_underflow behavior."""
        v = ArithmeticVerifier()
        x = z3.Int("x")
        y = z3.Int("y")
        expr = x - y
        res = v.check_underflow(expr, {"x": x, "y": y})
        assert res.is_disproven is True

    def test_check_division_safe(self) -> None:
        """Test check_division_safe behavior."""
        v = ArithmeticVerifier()
        x = z3.Int("x")
        y = z3.Int("y")
        res = v.check_division_safe(x, y, {"x": x, "y": y}, [y != 0])
        assert res.is_proven is True

    def test_check_array_bounds(self) -> None:
        """Test check_array_bounds behavior."""
        v = ArithmeticVerifier()
        idx = z3.Int("idx")
        res = v.check_array_bounds(idx, z3.IntVal(10), {"idx": idx}, [idx >= 0, idx < 10])
        assert res.is_proven is True


class TestEquivalenceChecker:
    """Test suite for pysymex.analysis.properties.core.EquivalenceChecker."""

    def test_check_equivalent(self) -> None:
        """Test check_equivalent behavior."""
        ec = EquivalenceChecker()
        res = ec.check_equivalent(lambda x: x + x, lambda x: 2 * x, [z3.Int("x")])
        assert res.is_proven is True

    def test_check_refinement(self) -> None:
        """Test check_refinement behavior."""
        ec = EquivalenceChecker()
        res = ec.check_refinement(lambda x: x > 0, lambda x: x > 5, [z3.Int("x")])
        assert res.is_proven is True
