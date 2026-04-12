import pytest
from unittest.mock import Mock, patch
from pysymex.analysis.specialized.strings import (
    StringWarningKind, StringWarning, PrintfFormatAnalyzer, StrFormatAnalyzer,
    FStringAnalyzer, RegexAnalyzer, SQLInjectionAnalyzer, PathTraversalAnalyzer,
    StringMultiplicationAnalyzer, StringAnalyzer
)

def make_dummy_code() -> object:
    def f() -> None:
        pass
    return f.__code__

class TestStringWarningKind:
    """Test suite for pysymex.analysis.specialized.strings.StringWarningKind."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert StringWarningKind.FORMAT_STRING_MISMATCH.name == "FORMAT_STRING_MISMATCH"
        assert StringWarningKind.SQL_INJECTION.name == "SQL_INJECTION"

class TestStringWarning:
    """Test suite for pysymex.analysis.specialized.strings.StringWarning."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        w = StringWarning(StringWarningKind.SQL_INJECTION, "f.py", 10, "msg")
        assert w.kind == StringWarningKind.SQL_INJECTION

class TestPrintfFormatAnalyzer:
    """Test suite for pysymex.analysis.specialized.strings.PrintfFormatAnalyzer."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        a = PrintfFormatAnalyzer()
        res = a.analyze("%s %d", ("a",), 10, "f.py")
        assert len(res) > 0
        assert res[0].kind == StringWarningKind.MISSING_FORMAT_ARG

class TestStrFormatAnalyzer:
    """Test suite for pysymex.analysis.specialized.strings.StrFormatAnalyzer."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        a = StrFormatAnalyzer()
        res = a.analyze("{}, {}", ("a",), {}, 10, "f.py")
        assert len(res) > 0
        assert res[0].kind == StringWarningKind.MISSING_FORMAT_ARG

class TestFStringAnalyzer:
    """Test suite for pysymex.analysis.specialized.strings.FStringAnalyzer."""
    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        a = FStringAnalyzer()
        res = a.analyze_source("f'{user_input}'")
        assert isinstance(res, list)

class TestRegexAnalyzer:
    """Test suite for pysymex.analysis.specialized.strings.RegexAnalyzer."""
    def test_analyze(self) -> None:
        """Test analyze behavior."""
        a = RegexAnalyzer()
        res = a.analyze("(a+)+", 10, "f.py")
        assert len(res) > 0
        assert res[0].kind == StringWarningKind.REGEX_PERFORMANCE

class TestSQLInjectionAnalyzer:
    """Test suite for pysymex.analysis.specialized.strings.SQLInjectionAnalyzer."""
    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        a = SQLInjectionAnalyzer()
        res = a.analyze_source("cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')")
        assert len(res) > 0
        assert res[0].kind == StringWarningKind.SQL_INJECTION

class TestPathTraversalAnalyzer:
    """Test suite for pysymex.analysis.specialized.strings.PathTraversalAnalyzer."""
    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        a = PathTraversalAnalyzer()
        res = a.analyze_source("open('/tmp/' + request['file'])")
        assert len(res) > 0
        assert res[0].kind == StringWarningKind.PATH_TRAVERSAL

class TestStringMultiplicationAnalyzer:
    """Test suite for pysymex.analysis.specialized.strings.StringMultiplicationAnalyzer."""
    @patch("pysymex.analysis.specialized.strings._cached_get_instructions")
    def test_analyze(self, mock_instrs) -> None:
        """Test analyze behavior."""
        mock_instrs.return_value = []
        a = StringMultiplicationAnalyzer()
        res = a.analyze(make_dummy_code()) # type: ignore[arg-type]
        assert isinstance(res, list)

class TestStringAnalyzer:
    """Test suite for pysymex.analysis.specialized.strings.StringAnalyzer."""
    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        a = StringAnalyzer()
        res = a.analyze_source("f'{x}'")
        assert isinstance(res, list)

    def test_analyze_function(self) -> None:
        """Test analyze_function behavior."""
        a = StringAnalyzer()
        res = a.analyze_function(make_dummy_code()) # type: ignore[arg-type]
        assert isinstance(res, list)

    def test_analyze_file(self) -> None:
        """Test analyze_file behavior."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
            f.write("f'{x}'")
            name = f.name
        
        try:
            a = StringAnalyzer()
            res = a.analyze_file(name)
            assert isinstance(res, list)
        finally:
            os.remove(name)
