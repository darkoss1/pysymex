import z3

import pysymex.core.types.floats as mod


class TestFloatPrecision:
    def test_initialization(self) -> None:
        assert mod.FloatPrecision.DOUBLE.name == "DOUBLE"


def test_get_fp_sort() -> None:
    sort_ref = mod.get_fp_sort(mod.FloatPrecision.SINGLE)
    assert isinstance(sort_ref, z3.FPSortRef)


class TestFloatConfig:
    def test_get_rounding_mode(self) -> None:
        config = mod.FloatConfig(rounding_mode="RTZ")
        assert isinstance(config.get_rounding_mode(), z3.FPRMRef)


class TestSymbolicFloat:
    def test_z3_expr(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_fp(sf.z3_expr)

    def test_is_nan(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_nan())

    def test_is_infinity(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_infinity())

    def test_is_positive_infinity(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_positive_infinity())

    def test_is_negative_infinity(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_negative_infinity())

    def test_is_zero(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_zero())

    def test_is_positive_zero(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_positive_zero())

    def test_is_negative_zero(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_negative_zero())

    def test_is_denormal(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_denormal())

    def test_is_normal(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_normal())

    def test_is_positive(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_positive())

    def test_is_negative(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_bool(sf.is_negative())

    def test_sqrt(self) -> None:
        sf = mod.AdvancedSymbolicFloat(value=4.0)
        assert isinstance(sf.sqrt(), mod.AdvancedSymbolicFloat)

    def test_fma(self) -> None:
        a = mod.AdvancedSymbolicFloat("a")
        b = mod.AdvancedSymbolicFloat("b")
        c = mod.AdvancedSymbolicFloat("c")
        assert isinstance(a.fma(b, c), mod.AdvancedSymbolicFloat)

    def test_min(self) -> None:
        a = mod.AdvancedSymbolicFloat("a")
        b = mod.AdvancedSymbolicFloat("b")
        assert isinstance(a.min(b), mod.AdvancedSymbolicFloat)

    def test_max(self) -> None:
        a = mod.AdvancedSymbolicFloat("a")
        b = mod.AdvancedSymbolicFloat("b")
        assert isinstance(a.max(b), mod.AdvancedSymbolicFloat)

    def test_to_int(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert z3.is_int(sf.to_int())

    def test_hash_value(self) -> None:
        sf = mod.AdvancedSymbolicFloat("x")
        assert isinstance(sf.hash_value(), int)

    def test_conditional_merge(self) -> None:
        a = mod.AdvancedSymbolicFloat("a")
        b = mod.AdvancedSymbolicFloat("b")
        merged = a.conditional_merge(b, z3.Bool("cond"))
        assert merged is not None


class TestFloatAnalyzer:
    def test_check_operation(self) -> None:
        analyzer = mod.FloatAnalyzer()
        result = mod.AdvancedSymbolicFloat("r")
        issues = analyzer.check_operation("add", result, [result], [])
        assert isinstance(issues, list)

    def test_check_comparison(self) -> None:
        analyzer = mod.FloatAnalyzer()
        left = mod.AdvancedSymbolicFloat("l")
        right = mod.AdvancedSymbolicFloat("r")
        issues = analyzer.check_comparison(left, right, [])
        assert isinstance(issues, list)

    def test_get_all_issues(self) -> None:
        analyzer = mod.FloatAnalyzer()
        assert analyzer.get_all_issues() == []


class TestAccuracyAnalyzer:
    def test_ulp_difference(self) -> None:
        analyzer = mod.AccuracyAnalyzer()
        a = mod.AdvancedSymbolicFloat("a")
        b = mod.AdvancedSymbolicFloat("b")
        assert z3.is_fp(analyzer.ulp_difference(a, b))

    def test_relative_error(self) -> None:
        analyzer = mod.AccuracyAnalyzer()
        a = mod.AdvancedSymbolicFloat("a")
        b = mod.AdvancedSymbolicFloat("b")
        assert isinstance(analyzer.relative_error(a, b), mod.AdvancedSymbolicFloat)

    def test_check_catastrophic_cancellation(self) -> None:
        analyzer = mod.AccuracyAnalyzer()
        a = mod.AdvancedSymbolicFloat("a")
        b = mod.AdvancedSymbolicFloat("b")
        r = mod.AdvancedSymbolicFloat("r")
        assert isinstance(analyzer.check_catastrophic_cancellation(a, b, r, []), bool)
