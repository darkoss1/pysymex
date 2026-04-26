import pytest
import tempfile
import os
from pysymex.analysis.exceptions.analyzer import (
    ExceptionASTAnalyzer,
    ExceptionBytecodeAnalyzer,
    UncaughtExceptionAnalyzer,
    ExceptionChainAnalyzer,
    ExceptionAnalyzer,
)
from pysymex.analysis.exceptions.types import ExceptionWarningKind


def make_dummy_code() -> object:
    def f() -> None:
        try:
            x = 1 / 0
        except ZeroDivisionError:
            pass

    return f.__code__


class TestExceptionASTAnalyzer:
    """Test suite for pysymex.analysis.exceptions.analyzer.ExceptionASTAnalyzer."""

    def test_visit_FunctionDef(self) -> None:
        """Test visit_FunctionDef behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        source = "def foo():\n    raise ValueError"
        analyzer.analyze(source)
        assert "ValueError" in analyzer.function_raises["foo"]

    def test_visit_AsyncFunctionDef(self) -> None:
        """Test visit_AsyncFunctionDef behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        source = "async def foo():\n    raise TypeError"
        analyzer.analyze(source)
        assert "TypeError" in analyzer.function_raises["foo"]

    def test_visit_Try(self) -> None:
        """Test visit_Try behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        source = """
try:
    raise ValueError
except:
    pass
finally:
    return 1
        """
        warnings = analyzer.analyze(source)
        kinds = [w.kind for w in warnings]
        assert ExceptionWarningKind.BARE_EXCEPT in kinds
        assert ExceptionWarningKind.FINALLY_RETURN in kinds
        assert ExceptionWarningKind.EXCEPTION_SWALLOWED in kinds

    def test_visit_Raise(self) -> None:
        """Test visit_Raise behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        source = "def f():\n    raise Exception('foo')"
        analyzer.analyze(source)
        assert "Exception" in analyzer.function_raises["f"]

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        analyzer = ExceptionASTAnalyzer("test.py")
        warnings = analyzer.analyze("try:\n    pass\nexcept BaseException:\n    pass")
        assert len(warnings) > 0
        assert any(w.kind == ExceptionWarningKind.TOO_BROAD_EXCEPT for w in warnings)


class TestExceptionBytecodeAnalyzer:
    """Test suite for pysymex.analysis.exceptions.analyzer.ExceptionBytecodeAnalyzer."""

    def test_analyze(self) -> None:
        """Test analyze behavior."""
        analyzer = ExceptionBytecodeAnalyzer()
        code = make_dummy_code()
        warnings = analyzer.analyze(code)
        assert isinstance(warnings, list)
        assert len(warnings) == 0


class TestUncaughtExceptionAnalyzer:
    """Test suite for pysymex.analysis.exceptions.analyzer.UncaughtExceptionAnalyzer."""

    def test_analyze(self) -> None:
        """Test analyze behavior."""

        def f(obj: object) -> None:
            x = obj.missing_attr

        analyzer = UncaughtExceptionAnalyzer()
        code = f.__code__
        potential = analyzer.analyze(code)
        assert len(potential) > 0
        has_attr = any("AttributeError" in errs for errs in potential.values())
        assert has_attr is True
        assert isinstance(potential, dict)


class TestExceptionChainAnalyzer:
    """Test suite for pysymex.analysis.exceptions.analyzer.ExceptionChainAnalyzer."""

    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        analyzer = ExceptionChainAnalyzer()
        warnings = analyzer.analyze_source("raise ValueError from e")
        assert isinstance(warnings, list)
        assert len(warnings) == 0


class TestExceptionAnalyzer:
    """Test suite for pysymex.analysis.exceptions.analyzer.ExceptionAnalyzer."""

    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        analyzer = ExceptionAnalyzer()
        warnings = analyzer.analyze_source("try:\n    pass\nexcept:\n    pass")
        assert len(warnings) > 0
        assert any(w.kind == ExceptionWarningKind.BARE_EXCEPT for w in warnings)

    def test_analyze_function(self) -> None:
        """Test analyze_function behavior."""
        analyzer = ExceptionAnalyzer()
        code = make_dummy_code()
        warnings = analyzer.analyze_function(code)
        assert isinstance(warnings, list)

    def test_analyze_file(self) -> None:
        """Test analyze_file behavior."""
        analyzer = ExceptionAnalyzer()
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
            f.write("try:\n    pass\nexcept:\n    pass")
            name = f.name

        try:
            warnings = analyzer.analyze_file(name)
            assert len(warnings) > 0
            assert any(w.kind == ExceptionWarningKind.BARE_EXCEPT for w in warnings)
        finally:
            os.remove(name)

    def test_get_potential_exceptions(self) -> None:
        """Test get_potential_exceptions behavior."""
        analyzer = ExceptionAnalyzer()
        code = make_dummy_code()
        pot = analyzer.get_potential_exceptions(code)
        assert isinstance(pot, dict)
