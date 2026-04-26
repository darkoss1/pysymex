import z3
from pysymex.contracts.quantifiers.types import QuantifierKind, QuantifierVar, BoundSpec, Quantifier


class TestQuantifierKind:
    """Test suite for pysymex.contracts.quantifiers.types.QuantifierKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert QuantifierKind.FORALL in QuantifierKind
        assert QuantifierKind.EXISTS in QuantifierKind
        assert QuantifierKind.UNIQUE in QuantifierKind
        assert QuantifierKind.COUNT in QuantifierKind


class TestQuantifierVar:
    """Test suite for pysymex.contracts.quantifiers.types.QuantifierVar."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        var = QuantifierVar("x", z3.IntSort())
        assert var.name == "x"
        assert z3.is_expr(var.z3_var)

        var_bool = QuantifierVar("b", z3.BoolSort())
        assert z3.is_bool(var_bool.z3_var)

        var_real = QuantifierVar("r", z3.RealSort())
        assert z3.is_real(var_real.z3_var)

        var_array = QuantifierVar("arr", z3.ArraySort(z3.IntSort(), z3.IntSort()))
        assert z3.is_array(var_array.z3_var)


class TestBoundSpec:
    """Test suite for pysymex.contracts.quantifiers.types.BoundSpec."""

    def test_to_constraint(self) -> None:
        """Test to_constraint behavior."""
        spec = BoundSpec(lower=z3.IntVal(0), upper=z3.IntVal(10))
        var = z3.Int("x")
        constraint = spec.to_constraint(var)
        assert z3.is_bool(constraint)

        spec_none = BoundSpec()
        assert z3.is_true(spec_none.to_constraint(var))

        assert z3.is_true(spec.to_constraint(None))

        collection = z3.Array("A", z3.IntSort(), z3.IntSort())
        spec_collection = BoundSpec(in_collection=collection)
        assert z3.is_bool(spec_collection.to_constraint(var))


class TestQuantifier:
    """Test suite for pysymex.contracts.quantifiers.types.Quantifier."""

    def test_to_z3(self) -> None:
        """Test to_z3 behavior."""
        var = QuantifierVar("x", z3.IntSort())
        spec = BoundSpec()
        body = z3.BoolVal(True)

        q_forall = Quantifier(QuantifierKind.FORALL, [var], [spec], body, "test")
        z3_forall = q_forall.to_z3()
        assert z3.is_bool(z3_forall)

        q_exists = Quantifier(QuantifierKind.EXISTS, [var], [spec], body, "test")
        z3_exists = q_exists.to_z3()
        assert z3.is_bool(z3_exists)

        q_unique = Quantifier(QuantifierKind.UNIQUE, [var], [spec], body, "test")
        z3_unique = q_unique.to_z3()
        assert z3.is_bool(z3_unique)
