"""Tests for pysymex.analysis.string_analysis -- String constraint analysis.

Covers:
- StringWarningKind enum values
- StringWarning creation
- PrintfFormatAnalyzer (% formatting)
- StrFormatAnalyzer (.format())
- FStringAnalyzer (f-strings)
- RegexAnalyzer (pattern validation and ReDoS)
- SQLInjectionAnalyzer (SQL injection detection)
- PathTraversalAnalyzer (path traversal detection)
- StringMultiplicationAnalyzer (bytecode-level)
- StringAnalyzer high-level interface
"""

from __future__ import annotations

import pytest

from pysymex.analysis.string_analysis import (
    FStringAnalyzer,
    PathTraversalAnalyzer,
    PrintfFormatAnalyzer,
    RegexAnalyzer,
    SQLInjectionAnalyzer,
    StrFormatAnalyzer,
    StringAnalyzer,
    StringMultiplicationAnalyzer,
    StringWarning,
    StringWarningKind,
)


# ===================================================================
# StringWarningKind enum
# ===================================================================


class TestStringWarningKind:
    """Tests for StringWarningKind enum values."""

    def test_format_string_mismatch_exists(self):
        assert StringWarningKind.FORMAT_STRING_MISMATCH is not None

    def test_missing_format_arg_exists(self):
        assert StringWarningKind.MISSING_FORMAT_ARG is not None

    def test_extra_format_arg_exists(self):
        assert StringWarningKind.EXTRA_FORMAT_ARG is not None

    def test_invalid_format_spec_exists(self):
        assert StringWarningKind.INVALID_FORMAT_SPEC is not None

    def test_invalid_regex_exists(self):
        assert StringWarningKind.INVALID_REGEX is not None

    def test_sql_injection_exists(self):
        assert StringWarningKind.SQL_INJECTION is not None

    def test_path_traversal_exists(self):
        assert StringWarningKind.PATH_TRAVERSAL is not None

    def test_all_members_distinct(self):
        values = [e.value for e in StringWarningKind]
        assert len(values) == len(set(values))


# ===================================================================
# StringWarning dataclass
# ===================================================================


class TestStringWarning:
    """Tests for StringWarning dataclass."""

    def test_creation(self):
        w = StringWarning(
            kind=StringWarningKind.SQL_INJECTION,
            file="test.py",
            line=10,
            message="potential injection",
        )
        assert w.kind == StringWarningKind.SQL_INJECTION
        assert w.file == "test.py"
        assert w.line == 10
        assert w.severity == "warning"

    def test_severity_override(self):
        w = StringWarning(
            kind=StringWarningKind.SQL_INJECTION,
            file="test.py",
            line=10,
            message="injection",
            severity="error",
        )
        assert w.severity == "error"


# ===================================================================
# PrintfFormatAnalyzer
# ===================================================================


class TestPrintfFormatAnalyzer:
    """Tests for printf-style format string analysis."""

    @pytest.fixture()
    def analyzer(self):
        return PrintfFormatAnalyzer()

    def test_correct_format_no_warnings(self, analyzer):
        warnings = analyzer.analyze("%d items", (5,), line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_missing_arg(self, analyzer):
        warnings = analyzer.analyze("%d %s", (5,), line=1, file_path="t.py")
        assert len(warnings) == 1
        assert warnings[0].kind == StringWarningKind.MISSING_FORMAT_ARG

    def test_extra_arg(self, analyzer):
        warnings = analyzer.analyze("%d", (5, 6), line=1, file_path="t.py")
        assert len(warnings) == 1
        assert warnings[0].kind == StringWarningKind.EXTRA_FORMAT_ARG

    def test_percent_literal_not_counted(self, analyzer):
        warnings = analyzer.analyze("100%%", (), line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_named_format(self, analyzer):
        warnings = analyzer.analyze("%(name)s", {"name": "x"}, line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_mixed_named_positional(self, analyzer):
        warnings = analyzer.analyze("%(name)s %d", (5,), line=1, file_path="t.py")
        assert any(w.kind == StringWarningKind.INVALID_FORMAT_SPEC for w in warnings)

    def test_star_width(self, analyzer):
        # %*d needs two args: width and value
        warnings = analyzer.analyze("%*d", (5, 10), line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_star_width_missing(self, analyzer):
        warnings = analyzer.analyze("%*d", (5,), line=1, file_path="t.py")
        assert len(warnings) == 1
        assert warnings[0].kind == StringWarningKind.MISSING_FORMAT_ARG

    def test_no_specs_no_warnings(self, analyzer):
        warnings = analyzer.analyze("hello world", (), line=1, file_path="t.py")
        assert len(warnings) == 0


# ===================================================================
# StrFormatAnalyzer
# ===================================================================


class TestStrFormatAnalyzer:
    """Tests for str.format() analysis."""

    @pytest.fixture()
    def analyzer(self):
        return StrFormatAnalyzer()

    def test_auto_numbering(self, analyzer):
        warnings = analyzer.analyze("{} {}", ("a", "b"), {}, line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_manual_numbering(self, analyzer):
        warnings = analyzer.analyze("{0} {1}", ("a", "b"), {}, line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_named_fields(self, analyzer):
        warnings = analyzer.analyze("{name}", (), {"name": "x"}, line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_missing_positional(self, analyzer):
        warnings = analyzer.analyze("{0} {1}", ("a",), {}, line=1, file_path="t.py")
        assert any(w.kind == StringWarningKind.MISSING_FORMAT_ARG for w in warnings)

    def test_missing_named(self, analyzer):
        warnings = analyzer.analyze("{name}", (), {}, line=1, file_path="t.py")
        assert any(w.kind == StringWarningKind.MISSING_FORMAT_ARG for w in warnings)

    def test_mixed_auto_manual(self, analyzer):
        warnings = analyzer.analyze("{} {0}", ("a",), {}, line=1, file_path="t.py")
        assert any(w.kind == StringWarningKind.INVALID_FORMAT_SPEC for w in warnings)

    def test_no_fields_no_warnings(self, analyzer):
        warnings = analyzer.analyze("hello", (), {}, line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_attribute_access(self, analyzer):
        warnings = analyzer.analyze("{0.name}", ("obj",), {}, line=1, file_path="t.py")
        assert len(warnings) == 0


# ===================================================================
# FStringAnalyzer
# ===================================================================


class TestFStringAnalyzer:
    """Tests for f-string analysis."""

    @pytest.fixture()
    def analyzer(self):
        return FStringAnalyzer()

    def test_simple_fstring(self, analyzer):
        source = 'x = 5\ny = f"value is {x}"'
        warnings = analyzer.analyze_source(source, "t.py")
        assert isinstance(warnings, list)

    def test_syntax_error_no_crash(self, analyzer):
        warnings = analyzer.analyze_source("this is not valid python (((", "t.py")
        assert warnings == []

    def test_no_fstrings(self, analyzer):
        source = 'x = "hello"\ny = 5'
        warnings = analyzer.analyze_source(source, "t.py")
        assert len(warnings) == 0


# ===================================================================
# RegexAnalyzer
# ===================================================================


class TestRegexAnalyzer:
    """Tests for regex pattern analysis."""

    @pytest.fixture()
    def analyzer(self):
        return RegexAnalyzer()

    def test_valid_pattern_no_warnings(self, analyzer):
        warnings = analyzer.analyze(r"\d+", line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_invalid_pattern(self, analyzer):
        warnings = analyzer.analyze(r"[invalid", line=1, file_path="t.py")
        assert len(warnings) == 1
        assert warnings[0].kind == StringWarningKind.INVALID_REGEX

    def test_nested_quantifiers_warning(self, analyzer):
        warnings = analyzer.analyze(r"(a+)+", line=1, file_path="t.py")
        assert any(w.kind == StringWarningKind.REGEX_PERFORMANCE for w in warnings)

    def test_multiple_dotstar_warning(self, analyzer):
        warnings = analyzer.analyze(r".*foo.*bar", line=1, file_path="t.py")
        assert any(w.kind == StringWarningKind.REGEX_PERFORMANCE for w in warnings)

    def test_simple_dotstar_no_warning(self, analyzer):
        warnings = analyzer.analyze(r"foo.*", line=1, file_path="t.py")
        assert len(warnings) == 0

    def test_single_dotstar_no_multiple_warning(self, analyzer):
        warnings = analyzer.analyze(r"^.*$", line=1, file_path="t.py")
        # Only one .* so no multiple dotstar warning
        perf_warnings = [w for w in warnings if w.kind == StringWarningKind.REGEX_PERFORMANCE]
        # Should not fire the "multiple .*" warning since count is 1
        assert not any("Multiple" in w.message for w in perf_warnings)


# ===================================================================
# SQLInjectionAnalyzer
# ===================================================================


class TestSQLInjectionAnalyzer:
    """Tests for SQL injection detection."""

    @pytest.fixture()
    def analyzer(self):
        return SQLInjectionAnalyzer()

    def test_string_concat_sql(self, analyzer):
        source = 'query = "SELECT * FROM users WHERE id=" + user_id'
        warnings = analyzer.analyze_source(source, "t.py")
        assert any(w.kind == StringWarningKind.SQL_INJECTION for w in warnings)

    def test_format_string_sql(self, analyzer):
        source = 'query = "SELECT * FROM users WHERE id=%s" % user_id'
        warnings = analyzer.analyze_source(source, "t.py")
        assert any(w.kind == StringWarningKind.SQL_INJECTION for w in warnings)

    def test_safe_query_no_warning(self, analyzer):
        source = 'x = "hello" + " world"'
        warnings = analyzer.analyze_source(source, "t.py")
        assert not any(w.kind == StringWarningKind.SQL_INJECTION for w in warnings)

    def test_execute_with_concat(self, analyzer):
        source = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)'
        warnings = analyzer.analyze_source(source, "t.py")
        assert any(w.kind == StringWarningKind.SQL_INJECTION for w in warnings)

    def test_execute_with_fstring(self, analyzer):
        source = 'cursor.execute(f"SELECT * FROM t WHERE id={uid}")'
        warnings = analyzer.analyze_source(source, "t.py")
        assert any(w.kind == StringWarningKind.SQL_INJECTION for w in warnings)

    def test_execute_parameterized_no_warning(self, analyzer):
        source = 'cursor.execute("SELECT * FROM t WHERE id=?", (uid,))'
        warnings = analyzer.analyze_source(source, "t.py")
        sql_warnings = [w for w in warnings if w.kind == StringWarningKind.SQL_INJECTION]
        assert len(sql_warnings) == 0

    def test_syntax_error_no_crash(self, analyzer):
        warnings = analyzer.analyze_source("not valid python (((", "t.py")
        assert warnings == []


# ===================================================================
# PathTraversalAnalyzer
# ===================================================================


class TestPathTraversalAnalyzer:
    """Tests for path traversal detection."""

    @pytest.fixture()
    def analyzer(self):
        return PathTraversalAnalyzer()

    def test_open_with_user_input(self, analyzer):
        source = 'open("/data/" + request["path"])'
        warnings = analyzer.analyze_source(source, "t.py")
        assert any(w.kind == StringWarningKind.PATH_TRAVERSAL for w in warnings)

    def test_open_with_fstring(self, analyzer):
        source = 'open(f"/data/{filename}")'
        warnings = analyzer.analyze_source(source, "t.py")
        assert any(w.kind == StringWarningKind.PATH_TRAVERSAL for w in warnings)

    def test_open_constant_no_warning(self, analyzer):
        source = 'open("/data/fixed_file.txt")'
        warnings = analyzer.analyze_source(source, "t.py")
        assert not any(w.kind == StringWarningKind.PATH_TRAVERSAL for w in warnings)

    def test_syntax_error_no_crash(self, analyzer):
        warnings = analyzer.analyze_source("not valid python (((", "t.py")
        assert warnings == []


# ===================================================================
# StringAnalyzer high-level
# ===================================================================


class TestStringAnalyzer:
    """Tests for StringAnalyzer high-level interface."""

    @pytest.fixture()
    def analyzer(self):
        return StringAnalyzer()

    def test_analyze_source_returns_list(self, analyzer):
        warnings = analyzer.analyze_source("x = 5", "t.py")
        assert isinstance(warnings, list)

    def test_analyze_source_sql_injection(self, analyzer):
        source = 'query = "SELECT * FROM t WHERE id=" + uid'
        warnings = analyzer.analyze_source(source, "t.py")
        assert any(w.kind == StringWarningKind.SQL_INJECTION for w in warnings)

    def test_analyze_function(self, analyzer):
        def _sample():
            return "hello"

        warnings = analyzer.analyze_function(_sample.__code__, "t.py")
        assert isinstance(warnings, list)

    def test_analyze_source_empty(self, analyzer):
        warnings = analyzer.analyze_source("", "t.py")
        assert isinstance(warnings, list)
