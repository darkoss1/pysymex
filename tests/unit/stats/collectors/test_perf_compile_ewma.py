"""Tests for pysymex.stats.collectors.perf — _compile_ewma fallback."""

from __future__ import annotations

from pysymex.stats.collectors.perf import _compile_ewma


class TestCompileEwmaFallback:
    """Test that _compile_ewma returns a usable function."""

    def test_compile_ewma_returns_callable(self) -> None:
        """_compile_ewma must return a callable regardless of numba."""

        def dummy(a: float, b: float, c: float) -> float:
            return a * c + b * (1.0 - c)

        compiled = _compile_ewma(dummy)
        assert callable(compiled)

    def test_compiled_function_produces_correct_result(self) -> None:
        """The compiled function must compute EWMA correctly."""

        def ewma(current: float, new_val: float, alpha: float) -> float:
            return alpha * new_val + (1.0 - alpha) * current

        compiled = _compile_ewma(ewma)
        result = compiled(10.0, 20.0, 0.5)
        expected = 0.5 * 20.0 + 0.5 * 10.0
        assert abs(result - expected) < 1e-9

    def test_compiled_function_with_zero_alpha(self) -> None:
        """Alpha=0 means the EWMA ignores the new value entirely."""

        def ewma(current: float, new_val: float, alpha: float) -> float:
            return alpha * new_val + (1.0 - alpha) * current

        compiled = _compile_ewma(ewma)
        result = compiled(42.0, 999.0, 0.0)
        assert abs(result - 42.0) < 1e-9

    def test_compiled_function_with_full_alpha(self) -> None:
        """Alpha=1 means the EWMA uses only the new value."""

        def ewma(current: float, new_val: float, alpha: float) -> float:
            return alpha * new_val + (1.0 - alpha) * current

        compiled = _compile_ewma(ewma)
        result = compiled(42.0, 999.0, 1.0)
        assert abs(result - 999.0) < 1e-9
