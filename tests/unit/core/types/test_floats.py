import pytest
import z3

from pysymex._internal.config.solver.floats import FloatConfig, FloatPrecision, get_fp_sort
from pysymex._internal.core.types.numeric.float import SymbolicFloat
from pysymex._internal.core.types.numeric.int import SymbolicInt


class TestFloatPrecision:
    def test_initialization(self) -> None:
        assert FloatPrecision.DOUBLE.name == "DOUBLE"


def test_get_fp_sort() -> None:
    sort_ref = get_fp_sort(FloatPrecision.SINGLE)
    assert isinstance(sort_ref, z3.FPSortRef)


class TestFloatConfig:
    def test_get_rounding_mode(self) -> None:
        config = FloatConfig(rounding_mode="RTZ")
        assert isinstance(config.get_rounding_mode(), z3.FPRMRef)


class TestSymbolicFloat:
    def test_z3_expr(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_fp(sf.z3_expr)

    def test_is_nan(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_nan())

    def test_is_infinity(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_infinity())

    def test_is_positive_infinity(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_positive_infinity())

    def test_is_negative_infinity(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_negative_infinity())

    def test_is_zero(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_zero())

    def test_is_positive_zero(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_positive_zero())

    def test_is_negative_zero(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_negative_zero())

    def test_is_denormal(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_denormal())

    def test_is_normal(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_normal())

    def test_is_positive(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_positive())

    def test_is_negative(self) -> None:
        sf = SymbolicFloat("x")
        assert z3.is_bool(sf.is_negative())

    def test_sqrt(self) -> None:
        sf = SymbolicFloat(value=4.0)
        assert isinstance(sf.sqrt(), SymbolicFloat)

    def test_fma(self) -> None:
        a = SymbolicFloat("a")
        b = SymbolicFloat("b")
        c = SymbolicFloat("c")
        assert isinstance(a.fma(b, c), SymbolicFloat)

    def test_min(self) -> None:
        a = SymbolicFloat("a")
        b = SymbolicFloat("b")
        assert isinstance(a.min(b), SymbolicFloat)

    def test_max(self) -> None:
        a = SymbolicFloat("a")
        b = SymbolicFloat("b")
        assert isinstance(a.max(b), SymbolicFloat)

    def test_to_int(self) -> None:
        sf = SymbolicFloat("x")
        assert isinstance(sf.to_int(), SymbolicInt)

    def test_hash_value(self) -> None:
        sf = SymbolicFloat("x")
        assert isinstance(sf.hash_value(), int)

    def test_conditional_merge(self) -> None:
        a = SymbolicFloat("a")
        b = SymbolicFloat("b")
        merged = a.conditional_merge(b, z3.Bool("cond"))
        assert merged is not None

    def test_modulo(self) -> None:
        a = SymbolicFloat(value=5.0)
        b = SymbolicFloat(value=2.0)
        res = a % b
        assert isinstance(res, SymbolicFloat)
        assert z3.is_true(z3.simplify(z3.fpEQ(res.z3_expr, z3.FPVal(1.0, z3.Float64()))))

        res_r = 5.0 % b
        assert isinstance(res_r, SymbolicFloat)
        assert z3.is_true(z3.simplify(z3.fpEQ(res_r.z3_expr, z3.FPVal(1.0, z3.Float64()))))

        large = SymbolicFloat(value=1e308) % 3.0
        assert z3.is_true(z3.simplify(z3.fpEQ(large.z3_expr, z3.FPVal(2.0, z3.Float64()))))

        symbolic = SymbolicFloat(name="symbolic_modulo")
        symbolic_result = symbolic % -3.0
        substituted = z3.simplify(
            z3.substitute(
                symbolic_result.z3_expr,
                (symbolic.z3_expr, z3.FPVal(6.0, z3.Float64())),
            )
        )
        assert z3.is_true(z3.simplify(z3.fpIsZero(substituted)))
        assert z3.is_true(z3.simplify(z3.fpIsNegative(substituted)))

    def test_modulo_by_concrete_zero_raises(self) -> None:
        with pytest.raises(ZeroDivisionError, match="float modulo"):
            _ = SymbolicFloat(value=5.0) % 0.0

        with pytest.raises(ZeroDivisionError, match="float modulo"):
            _ = 5.0 % SymbolicFloat(value=0.0)

    def test_pow(self) -> None:
        a = SymbolicFloat(value=2.0)
        b = SymbolicFloat(value=3.0)
        res = a**b
        assert isinstance(res, SymbolicFloat)
        assert z3.is_true(z3.simplify(z3.fpEQ(res.z3_expr, z3.FPVal(8.0, z3.Float64()))))

        res_r = 2.0**b
        assert isinstance(res_r, SymbolicFloat)
        assert z3.is_true(z3.simplify(z3.fpEQ(res_r.z3_expr, z3.FPVal(8.0, z3.Float64()))))

    def test_pow_preserves_concrete_python_failures(self) -> None:
        with pytest.raises(ZeroDivisionError):
            _ = SymbolicFloat(value=0.0) ** -1.0

        with pytest.raises(TypeError, match="complex"):
            _ = SymbolicFloat(value=-2.0) ** 0.5
