import z3

from pysymex.core.types.advanced_float import AdvancedSymbolicFloat
from pysymex.config.floats import FloatConfig, FloatPrecision, get_fp_sort


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
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_fp(sf.z3_expr)

    def test_is_nan(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_nan())

    def test_is_infinity(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_infinity())

    def test_is_positive_infinity(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_positive_infinity())

    def test_is_negative_infinity(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_negative_infinity())

    def test_is_zero(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_zero())

    def test_is_positive_zero(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_positive_zero())

    def test_is_negative_zero(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_negative_zero())

    def test_is_denormal(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_denormal())

    def test_is_normal(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_normal())

    def test_is_positive(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_positive())

    def test_is_negative(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_negative())

    def test_sqrt(self) -> None:
        sf = AdvancedSymbolicFloat(value=4.0)
        assert isinstance(sf.sqrt(), AdvancedSymbolicFloat)

    def test_fma(self) -> None:
        a = AdvancedSymbolicFloat("a")
        b = AdvancedSymbolicFloat("b")
        c = AdvancedSymbolicFloat("c")
        assert isinstance(a.fma(b, c), AdvancedSymbolicFloat)

    def test_min(self) -> None:
        a = AdvancedSymbolicFloat("a")
        b = AdvancedSymbolicFloat("b")
        assert isinstance(a.min(b), AdvancedSymbolicFloat)

    def test_max(self) -> None:
        a = AdvancedSymbolicFloat("a")
        b = AdvancedSymbolicFloat("b")
        assert isinstance(a.max(b), AdvancedSymbolicFloat)

    def test_to_int(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert z3.is_int(sf.to_int())

    def test_hash_value(self) -> None:
        sf = AdvancedSymbolicFloat("x")
        assert isinstance(sf.hash_value(), int)

    def test_conditional_merge(self) -> None:
        a = AdvancedSymbolicFloat("a")
        b = AdvancedSymbolicFloat("b")
        merged = a.conditional_merge(b, z3.Bool("cond"))
        assert merged is not None
