"""Tests for floating-point symbolic analysis."""

import pytest

import z3


from pysymex.core.floats import (
    FloatPrecision,
    FloatConfig,
    SymbolicFloat,
    FloatAnalyzer,
    AccuracyAnalyzer,
    get_fp_sort,
)


class TestFloatPrecision:
    """Tests for FloatPrecision enum."""

    def test_precision_values(self):
        """Test precision enum has expected values."""

        assert FloatPrecision.HALF is not None

        assert FloatPrecision.SINGLE is not None

        assert FloatPrecision.DOUBLE is not None

        assert FloatPrecision.EXTENDED is not None

        assert FloatPrecision.QUAD is not None

    def test_precision_to_sort(self):
        """Test converting precision to Z3 sort."""

        for precision in FloatPrecision:
            sort = get_fp_sort(precision)

            assert sort is not None

            assert isinstance(sort, z3.FPSortRef)


class TestFloatConfig:
    """Tests for FloatConfig."""

    def test_default_config(self):
        """Test default configuration."""

        config = FloatConfig()

        assert config.precision == FloatPrecision.DOUBLE

        assert config.rounding_mode is not None

    def test_custom_precision(self):
        """Test custom precision."""

        config = FloatConfig(precision=FloatPrecision.SINGLE)

        assert config.precision == FloatPrecision.SINGLE

    def test_get_rounding_mode(self):
        """Test getting rounding mode."""

        config = FloatConfig()

        rm = config.get_rounding_mode()

        assert rm is not None


class TestSymbolicFloat:
    """Tests for SymbolicFloat."""

    def test_create_symbolic_float(self):
        """Test creating a symbolic float."""

        sf = SymbolicFloat("x")

        assert sf.name == "x"

        assert sf.z3_expr is not None

    def test_create_with_config(self):
        """Test creating float with specific config."""

        config = FloatConfig(precision=FloatPrecision.SINGLE)

        sf = SymbolicFloat("x", config=config)

        assert sf.config.precision == FloatPrecision.SINGLE

    def test_from_value(self):
        """Test creating float from concrete value."""

        sf = SymbolicFloat(name="pi", value=3.14)

        assert sf is not None

        assert sf.name == "pi"

    def test_addition(self):
        """Test symbolic float addition."""

        a = SymbolicFloat("a")

        b = SymbolicFloat("b")

        c = a + b

        assert c is not None

        assert c.z3_expr is not None

    def test_subtraction(self):
        """Test symbolic float subtraction."""

        a = SymbolicFloat("a")

        b = SymbolicFloat("b")

        c = a - b

        assert c is not None

    def test_multiplication(self):
        """Test symbolic float multiplication."""

        a = SymbolicFloat("a")

        b = SymbolicFloat("b")

        c = a * b

        assert c is not None

    def test_division(self):
        """Test symbolic float division."""

        a = SymbolicFloat("a")

        b = SymbolicFloat("b")

        c = a / b

        assert c is not None

    def test_negation(self):
        """Test symbolic float negation."""

        a = SymbolicFloat("a")

        b = -a

        assert b is not None

    def test_comparison_lt(self):
        """Test less-than comparison."""

        a = SymbolicFloat("a")

        b = SymbolicFloat("b")

        cond = a < b

        assert cond is not None

        assert isinstance(cond, z3.BoolRef)

    def test_comparison_eq(self):
        """Test equality comparison."""

        a = SymbolicFloat("a")

        b = SymbolicFloat("b")

        cond = a == b

        assert cond is not None

        assert isinstance(cond, z3.BoolRef)

    def test_is_nan(self):
        """Test NaN check."""

        a = SymbolicFloat("a")

        cond = a.is_nan()

        assert cond is not None

        assert isinstance(cond, z3.BoolRef)

    def test_is_infinity(self):
        """Test infinity check."""

        a = SymbolicFloat("a")

        cond = a.is_infinity()

        assert cond is not None

    def test_is_zero(self):
        """Test zero check."""

        a = SymbolicFloat("a")

        cond = a.is_zero()

        assert cond is not None

    def test_is_negative(self):
        """Test negative check."""

        a = SymbolicFloat("a")

        cond = a.is_negative()

        assert cond is not None

    def test_abs(self):
        """Test absolute value."""

        a = SymbolicFloat("a")

        b = abs(a)

        assert b is not None

    def test_sqrt(self):
        """Test square root."""

        a = SymbolicFloat("a")

        b = a.sqrt()

        assert b is not None

    def test_fma(self):
        """Test fused multiply-add."""

        a = SymbolicFloat("a")

        b = SymbolicFloat("b")

        c = SymbolicFloat("c")

        result = a.fma(b, c)

        assert result is not None


class TestFloatAnalyzer:
    """Tests for FloatAnalyzer."""

    def test_create_analyzer(self):
        """Test creating float analyzer."""

        analyzer = FloatAnalyzer()

        assert analyzer is not None

        assert analyzer.config is not None

    def test_get_all_issues(self):
        """Test getting all detected issues."""

        analyzer = FloatAnalyzer()

        issues = analyzer.get_all_issues()

        assert isinstance(issues, list)


class TestAccuracyAnalyzer:
    """Tests for AccuracyAnalyzer."""

    def test_create_analyzer(self):
        """Test creating accuracy analyzer."""

        analyzer = AccuracyAnalyzer()

        assert analyzer is not None


class TestFloatSolving:
    """Tests for solving float constraints."""

    def test_solve_float_constraint(self):
        """Test solving a float constraint."""

        x = SymbolicFloat("x")

        solver = z3.Solver()

        solver.add(z3.Not(x.is_nan()))

        solver.add(x > 0.0)

        result = solver.check()

        assert result == z3.sat

    def test_nan_propagation(self):
        """Test NaN propagation."""

        nan = SymbolicFloat("nan")

        x = SymbolicFloat("x")

        solver = z3.Solver()

        solver.add(nan.is_nan())

        result = nan + x

        solver.add(result.is_nan())

        assert solver.check() == z3.sat
