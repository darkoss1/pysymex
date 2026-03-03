"""Tests for v0.5.0 remaining roadmap items (Steps 1-6).

Step 1: TOO_BROAD_EXCEPT narrowing (crashy API suppression)
Step 2: Context-sensitive exception analysis (handler intent)
Step 3: Actionable suggestions on every finding (SUGGESTION_MAP)
Step 4: Group related findings in reports
Step 5: Cross-function return type inference
Step 6: Abstract interpretation fast-path for trivial functions
"""

import dis

import json

import pytest


from pysymex.analysis.exceptions.analysis import (
    ExceptionASTAnalyzer,
    ExceptionWarningKind,
    HandlerIntent,
    _classify_handler_intent,
    _try_body_calls_crashy_api,
    KNOWN_CRASHY_APIS,
)

from pysymex.analysis.pipeline import (
    ScanIssue,
    Scanner,
    IssueCategory,
    ScannerConfig,
    SUGGESTION_MAP,
    _attach_suggestion,
    _group_issues,
    _extract_var_name_from_message,
)

from pysymex.analysis.cross_function import (
    _infer_return_type,
    _PYTHON_TYPE_TO_PYTYPE,
)

from pysymex.analysis.type_inference import PyType, TypeKind

from pysymex.analysis.abstract.interpreter import (
    AbstractInterpreter,
    AbstractWarning,
)


import ast


def _compile(source: str, name: str = "<test>"):
    return compile(source, name, "exec")


def _compile_function(source: str, func_name: str):
    module_code = compile(source, "<test>", "exec")

    for const in module_code.co_consts:
        if hasattr(const, "co_code") and getattr(const, "co_name", None) == func_name:
            return const

    raise ValueError(f"Function '{func_name}' not found")


def _parse_try(source: str) -> ast.Try:
    """Parse source and return the first ast.Try node."""

    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            return node

    raise ValueError("No try node found")


def _make_issue(kind, message, function_name="", line=1, confidence=1.0, suggestion=""):
    return ScanIssue(
        category=IssueCategory.DEAD_CODE,
        kind=kind,
        severity="warning",
        file="<test>",
        line=line,
        message=message,
        confidence=confidence,
        function_name=function_name,
        detected_by=["test"],
        suggestion=suggestion,
    )


class TestCrashyAPISuppression:
    """Step 1: except Exception wrapping known-crashy APIs should be suppressed."""

    def test_z3_call_detected_as_crashy(self):
        """Try body calling z3.solve() should be detected as crashy."""

        source = """\
try:
    result = z3.solve(expr)
except Exception:
    return None
"""

        try_node = _parse_try(source)

        assert _try_body_calls_crashy_api(try_node)

    def test_json_loads_detected_as_crashy(self):
        """Try body calling json.loads() should be detected as crashy."""

        source = """\
try:
    data = json.loads(raw)
except Exception:
    return {}
"""

        try_node = _parse_try(source)

        assert _try_body_calls_crashy_api(try_node)

    def test_regular_code_not_crashy(self):
        """Try body with regular code should not be detected as crashy."""

        source = """\
try:
    result = x + y
except Exception:
    pass
"""

        try_node = _parse_try(source)

        assert not _try_body_calls_crashy_api(try_node)

    def test_crashy_api_with_safety_net_suppressed(self):
        """except Exception wrapping crashy API with return should be suppressed."""

        source = """\
try:
    result = z3.solve(expr)
except Exception:
    return None
"""

        analyzer = ExceptionASTAnalyzer("<test>")

        warnings = analyzer.analyze(source)

        broad_warnings = [w for w in warnings if w.kind == ExceptionWarningKind.TOO_BROAD_EXCEPT]

        assert len(broad_warnings) == 0

    def test_crashy_api_with_logging_suppressed(self):
        """except Exception wrapping crashy API with logging should be suppressed."""

        source = """\
try:
    result = json.loads(raw)
except Exception:
    logger.error("Failed to parse")
    return {}
"""

        analyzer = ExceptionASTAnalyzer("<test>")

        warnings = analyzer.analyze(source)

        broad_warnings = [w for w in warnings if w.kind == ExceptionWarningKind.TOO_BROAD_EXCEPT]

        assert len(broad_warnings) == 0

    def test_regular_code_with_pass_still_flagged(self):
        """except Exception with pass on regular code should still be flagged."""

        source = """\
try:
    x = calculate(a, b)
except Exception:
    pass
"""

        analyzer = ExceptionASTAnalyzer("<test>")

        warnings = analyzer.analyze(source)

        broad_warnings = [w for w in warnings if w.kind == ExceptionWarningKind.TOO_BROAD_EXCEPT]

        assert len(broad_warnings) >= 1

        assert broad_warnings[0].severity == "warning"

    def test_base_exception_always_flagged(self):
        """except BaseException should always be flagged regardless of context."""

        source = """\
try:
    result = z3.solve(expr)
except BaseException:
    return None
"""

        analyzer = ExceptionASTAnalyzer("<test>")

        warnings = analyzer.analyze(source)

        broad_warnings = [w for w in warnings if w.kind == ExceptionWarningKind.TOO_BROAD_EXCEPT]

        assert len(broad_warnings) >= 1

        assert broad_warnings[0].severity == "error"


class TestHandlerIntentClassification:
    """Step 2: Handler intent classification."""

    def test_safety_net_with_return(self):
        """Handler with return should be classified as SAFETY_NET."""

        source = """\
try:
    x = 1
except Exception as e:
    return None
"""

        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                intent = _classify_handler_intent(node)

                assert intent == HandlerIntent.SAFETY_NET

    def test_safety_net_with_raise(self):
        """Handler with raise should be classified as SAFETY_NET."""

        source = """\
try:
    x = 1
except ValueError as e:
    raise RuntimeError("fail") from e
"""

        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                intent = _classify_handler_intent(node)

                assert intent == HandlerIntent.SAFETY_NET

    def test_silenced_with_pass(self):
        """Handler with bare pass should be classified as SILENCED."""

        source = """\
try:
    x = 1
except Exception:
    pass
"""

        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                intent = _classify_handler_intent(node)

                assert intent == HandlerIntent.SILENCED

    def test_logged_with_logger(self):
        """Handler with logging call should be classified as LOGGED."""

        source = """\
try:
    x = 1
except Exception as e:
    logger.exception("Failed")
"""

        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                intent = _classify_handler_intent(node)

                assert intent == HandlerIntent.LOGGED

    def test_safety_net_severity_is_info(self):
        """Handler with return fallback should produce info-severity warning."""

        source = """\
try:
    x = calculate()
except Exception:
    return None
"""

        analyzer = ExceptionASTAnalyzer("<test>")

        warnings = analyzer.analyze(source)

        broad = [w for w in warnings if w.kind == ExceptionWarningKind.TOO_BROAD_EXCEPT]

        assert len(broad) >= 1

        assert broad[0].severity == "info"

    def test_silenced_severity_is_warning(self):
        """Handler with pass should produce warning-severity warning."""

        source = """\
try:
    x = calculate()
except Exception:
    pass
"""

        analyzer = ExceptionASTAnalyzer("<test>")

        warnings = analyzer.analyze(source)

        broad = [w for w in warnings if w.kind == ExceptionWarningKind.TOO_BROAD_EXCEPT]

        assert len(broad) >= 1

        assert broad[0].severity == "warning"


class TestActionableSuggestions:
    """Step 3: Every finding should have an actionable suggestion."""

    def test_known_kind_gets_suggestion(self):
        """Known issue kind should get a suggestion from SUGGESTION_MAP."""

        issue = _make_issue("UNUSED_VARIABLE", "Variable 'x' is assigned but never used")

        _attach_suggestion(issue)

        assert issue.suggestion != ""

        assert "Remove" in issue.suggestion or "prefix" in issue.suggestion

    def test_unknown_kind_gets_empty_suggestion(self):
        """Unknown issue kind should get empty suggestion gracefully."""

        issue = _make_issue("SOME_UNKNOWN_KIND", "Unknown issue")

        _attach_suggestion(issue)

        assert issue.suggestion == ""

    def test_suggestion_not_overwritten(self):
        """If issue already has a suggestion, it should not be overwritten."""

        issue = _make_issue(
            "UNUSED_VARIABLE",
            "Variable 'x' is unused",
            suggestion="Custom suggestion",
        )

        _attach_suggestion(issue)

        assert issue.suggestion == "Custom suggestion"

    def test_suggestion_in_text_report(self):
        """Suggestion should appear in generated text report."""

        scanner = Scanner(
            ScannerConfig(
                enable_type_inference=False,
                enable_flow_analysis=False,
                enable_pattern_recognition=False,
                enable_abstract_interpretation=False,
                enable_cross_function=False,
                enable_resource_analysis=False,
                enable_exception_analysis=False,
                enable_string_analysis=False,
                enable_taint_analysis=False,
            )
        )

        issue = _make_issue(
            "UNUSED_VARIABLE",
            "Variable 'x' is assigned but never used",
            suggestion="Remove the variable",
        )

        report = scanner.generate_report([issue], format="text")

        assert "Remove the variable" in report

    def test_suggestion_in_json_report(self):
        """Suggestion should appear in JSON report output."""

        scanner = Scanner(
            ScannerConfig(
                enable_type_inference=False,
                enable_flow_analysis=False,
                enable_pattern_recognition=False,
                enable_abstract_interpretation=False,
                enable_cross_function=False,
                enable_resource_analysis=False,
                enable_exception_analysis=False,
                enable_string_analysis=False,
                enable_taint_analysis=False,
            )
        )

        issue = _make_issue(
            "UNUSED_VARIABLE",
            "Variable 'x' is assigned but never used",
            suggestion="Remove the variable",
        )

        report = scanner.generate_report([issue], format="json")

        data = json.loads(report)

        assert len(data["issues"]) == 1

        assert data["issues"][0]["suggestion"] == "Remove the variable"

    def test_all_common_kinds_have_suggestions(self):
        """All commonly detected kinds should have entries in SUGGESTION_MAP."""

        common_kinds = [
            "UNUSED_VARIABLE",
            "UNUSED_IMPORT",
            "DEAD_STORE",
            "UNREACHABLE_CODE",
            "DIVISION_BY_ZERO",
            "TOO_BROAD_EXCEPT",
        ]

        for kind in common_kinds:
            assert kind in SUGGESTION_MAP, f"Missing suggestion for {kind}"


class TestGroupRelatedFindings:
    """Step 4: Reports should group 3+ same-kind issues in same function."""

    def test_group_issues_basic(self):
        """3+ issues of same kind in same function should be grouped."""

        issues = [
            _make_issue(
                "UNUSED_VARIABLE", f"Variable 'v{i}' is unused", function_name="foo", line=i
            )
            for i in range(5)
        ]

        groups = _group_issues(issues)

        key = ("<test>", "foo", "UNUSED_VARIABLE")

        assert key in groups

        assert len(groups[key]) == 5

    def test_group_issues_different_functions_separate(self):
        """Issues in different functions should not be grouped together."""

        issues = [
            _make_issue("UNUSED_VARIABLE", "Variable 'x' is unused", function_name="foo", line=1),
            _make_issue("UNUSED_VARIABLE", "Variable 'y' is unused", function_name="bar", line=2),
        ]

        groups = _group_issues(issues)

        assert len(groups) == 2

    def test_json_report_includes_groups(self):
        """JSON report should include a 'groups' key."""

        scanner = Scanner(
            ScannerConfig(
                enable_type_inference=False,
                enable_flow_analysis=False,
                enable_pattern_recognition=False,
                enable_abstract_interpretation=False,
                enable_cross_function=False,
                enable_resource_analysis=False,
                enable_exception_analysis=False,
                enable_string_analysis=False,
                enable_taint_analysis=False,
            )
        )

        issues = [
            _make_issue(
                "UNUSED_VARIABLE", f"Variable 'v{i}' is unused", function_name="foo", line=i
            )
            for i in range(5)
        ]

        report = scanner.generate_report(issues, format="json")

        data = json.loads(report)

        assert "groups" in data

        assert len(data["groups"]) >= 1

        assert data["groups"][0]["count"] == 5

    def test_single_issue_not_grouped(self):
        """Single issue should not trigger grouping."""

        scanner = Scanner(
            ScannerConfig(
                enable_type_inference=False,
                enable_flow_analysis=False,
                enable_pattern_recognition=False,
                enable_abstract_interpretation=False,
                enable_cross_function=False,
                enable_resource_analysis=False,
                enable_exception_analysis=False,
                enable_string_analysis=False,
                enable_taint_analysis=False,
            )
        )

        issues = [
            _make_issue("UNUSED_VARIABLE", "Variable 'x' is unused", function_name="foo", line=1),
        ]

        report = scanner.generate_report(issues, format="json")

        data = json.loads(report)

        assert len(data["groups"]) == 0

    def test_text_report_shows_group_summary(self):
        """Text report should show a group summary line for 3+ same-kind issues."""

        scanner = Scanner(
            ScannerConfig(
                enable_type_inference=False,
                enable_flow_analysis=False,
                enable_pattern_recognition=False,
                enable_abstract_interpretation=False,
                enable_cross_function=False,
                enable_resource_analysis=False,
                enable_exception_analysis=False,
                enable_string_analysis=False,
                enable_taint_analysis=False,
            )
        )

        issues = [
            _make_issue(
                "UNUSED_VARIABLE", f"Variable 'v{i}' is unused", function_name="foo", line=i
            )
            for i in range(4)
        ]

        report = scanner.generate_report(issues, format="text")

        assert "4 unused variable findings" in report


class TestReturnTypeInference:
    """Step 5: Infer return type from RETURN_VALUE/RETURN_CONST bytecode."""

    def test_return_int_constant(self):
        """Function returning int constant should infer INT type."""

        source = """\
def get_value():
    return 42
"""

        code = _compile_function(source, "get_value")

        result = _infer_return_type(code)

        assert result is not None

        assert result.kind == TypeKind.INT

    def test_return_string_constant(self):
        """Function returning string should infer STR type."""

        source = """\
def get_name():
    return "hello"
"""

        code = _compile_function(source, "get_name")

        result = _infer_return_type(code)

        assert result is not None

        assert result.kind == TypeKind.STR

    def test_return_none(self):
        """Function returning None should infer NONE type."""

        source = """\
def do_nothing():
    return None
"""

        code = _compile_function(source, "do_nothing")

        result = _infer_return_type(code)

        assert result is not None

        assert result.kind == TypeKind.NONE

    def test_no_return_statement(self):
        """Function with no return should infer NONE type."""

        source = """\
def side_effect():
    x = 1
"""

        code = _compile_function(source, "side_effect")

        result = _infer_return_type(code)

        assert result is not None

        assert result.kind == TypeKind.NONE

    def test_return_bool_constant(self):
        """Function returning bool should infer BOOL type."""

        source = """\
def is_valid():
    return True
"""

        code = _compile_function(source, "is_valid")

        result = _infer_return_type(code)

        assert result is not None

        assert result.kind == TypeKind.BOOL


class TestAbstractInterpretationFastPath:
    """Step 6: Trivial functions should use fast-path analysis."""

    def test_trivial_function_uses_fast_path(self):
        """Simple function should be detected as trivial."""

        source = """\
def add(a, b):
    return a + b
"""

        code = _compile_function(source, "add")

        assert AbstractInterpreter._is_trivial(code)

    def test_trivial_function_no_warnings(self):
        """Trivial function with no issues should produce no warnings."""

        source = """\
def add(a, b):
    return a + b
"""

        code = _compile_function(source, "add")

        interp = AbstractInterpreter()

        warnings = interp.analyze(code, "<test>")

        assert len(warnings) == 0

        assert interp._used_fast_path is True

    def test_function_with_loop_not_trivial(self):
        """Function with loop should NOT be trivial."""

        source = """\
def sum_list(items):
    total = 0
    for item in items:
        total += item
    return total
"""

        code = _compile_function(source, "sum_list")

        assert not AbstractInterpreter._is_trivial(code)

    def test_function_with_many_instructions_not_trivial(self):
        """Function with 20+ instructions should NOT be trivial."""

        lines = ["def big():"]

        for i in range(20):
            lines.append(f"    x{i} = {i}")

        lines.append(f"    return x0")

        source = "\n".join(lines)

        code = _compile_function(source, "big")

        assert not AbstractInterpreter._is_trivial(code)

    def test_abstract_warning_dataclass(self):
        """AbstractWarning should be a valid dataclass."""

        w = AbstractWarning(
            kind="DIVISION_BY_ZERO",
            message="Division by literal zero",
            file="<test>",
            line=10,
            pc=42,
        )

        assert w.kind == "DIVISION_BY_ZERO"

        assert w.line == 10

        assert w.pc == 42

    def test_full_analysis_for_non_trivial(self):
        """Non-trivial functions should not use fast-path."""

        source = """\
def classify(x):
    if x > 0:
        return 1
    else:
        return -1
"""

        code = _compile_function(source, "classify")

        assert not AbstractInterpreter._is_trivial(code)
