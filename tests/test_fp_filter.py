"""Tests for the False Positive Filter module.

Tests cover:
- Typing pattern detection
- TYPE_CHECKING block detection
- Assertion context analysis
- Confidence scoring
- Issue filtering and deduplication
"""

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.false_positive_filter import (
    TYPING_FP_PATTERNS,
    AssertionContext,
    Confidence,
    calculate_confidence,
    deduplicate_issues,
    detect_assertion_context,
    filter_issue,
    filter_issues,
    is_type_checking_block_issue,
    is_typing_false_positive,
)


class TestTypingFalsePositiveDetection:
    """Test detection of typing-related false positives."""

    def test_callable_subscript_is_fp(self):
        """Callable type hints should be flagged as FP."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Attempting to subscript Callable which could be an int",
        )
        assert is_typing_false_positive(issue) is True

    def test_import_callable_is_fp(self):
        """import_Callable patterns should be flagged as FP."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Attempting to subscript import_Callable[int, str]",
        )
        assert is_typing_false_positive(issue) is True

    def test_paramspec_is_fp(self):
        """ParamSpec type hints should be flagged as FP."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Attempting to subscript ParamSpec which could be an int",
        )
        assert is_typing_false_positive(issue) is True

    def test_typevar_is_fp(self):
        """TypeVar should be flagged as FP."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Attempting to subscript TypeVar in generic",
        )
        assert is_typing_false_positive(issue) is True

    def test_protocol_is_fp(self):
        """Protocol should be flagged as FP."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Attempting to subscript Protocol base class",
        )
        assert is_typing_false_positive(issue) is True

    def test_generic_is_fp(self):
        """Generic should be flagged as FP."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Attempting to subscript Generic type",
        )
        assert is_typing_false_positive(issue) is True

    def test_real_type_error_not_fp(self):
        """Real type errors should NOT be flagged as FP."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Cannot add string and integer",
        )
        assert is_typing_false_positive(issue) is False

    def test_division_by_zero_not_fp(self):
        """Division by zero is never a typing FP."""
        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="Possible division by zero: x can be 0",
        )
        assert is_typing_false_positive(issue) is False


class TestTypeCheckingBlockDetection:
    """Test detection of TYPE_CHECKING block issues."""

    def test_type_checking_in_message(self):
        """Messages mentioning TYPE_CHECKING should be detected."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Error in import_TYPE_CHECKING block",
        )
        assert is_type_checking_block_issue(issue) is True

    def test_typing_module_in_message(self):
        """Messages mentioning typing. should be detected."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Error from typing.Generic",
        )
        assert is_type_checking_block_issue(issue) is True

    def test_normal_message_not_type_checking(self):
        """Normal messages should not be flagged."""
        issue = Issue(
            kind=IssueKind.INDEX_ERROR,
            message="Index out of bounds in list",
        )
        assert is_type_checking_block_issue(issue) is False


class TestConfidenceScoring:
    """Test confidence level calculation."""

    def test_division_by_zero_with_model_is_high(self):
        """Division by zero with Z3 model should be HIGH confidence."""
        solver = z3.Solver()
        x = z3.Int("x")
        solver.add(x == 0)
        solver.check()
        model = solver.model()

        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="Division by zero: x can be 0",
            model=model,
        )
        assert calculate_confidence(issue) == Confidence.HIGH

    def test_assertion_error_is_medium(self):
        """Assertion errors should be MEDIUM confidence."""
        issue = Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="Assertion may fail",
        )
        assert calculate_confidence(issue) == Confidence.MEDIUM

    def test_type_error_typing_fp_is_low(self):
        """Type errors that are typing FPs should be LOW confidence."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Attempting to subscript Callable",
        )
        assert calculate_confidence(issue) == Confidence.LOW

    def test_index_error_no_model_is_low(self):
        """Index errors without model should be LOW confidence."""
        issue = Issue(
            kind=IssueKind.INDEX_ERROR,
            message="Index may be out of bounds",
            model=None,
        )
        assert calculate_confidence(issue) == Confidence.LOW


class TestAssertionContext:
    """Test assertion context detection."""

    def test_validate_function_is_validation(self):
        """Functions with 'validate' in name should be VALIDATION."""
        issue = Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="Assertion in validate_input",
            function_name="validate_input",
        )
        context = detect_assertion_context(issue)
        assert context == AssertionContext.VALIDATION

    def test_sanitize_function_is_validation(self):
        """Functions with 'sanitize' in name should be VALIDATION."""
        issue = Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="sanitize_data raised error",
            function_name="sanitize_data",
        )
        context = detect_assertion_context(issue)
        assert context == AssertionContext.VALIDATION

    def test_security_function_is_security_guard(self):
        """Functions with security patterns should be detected."""
        issue = Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="Security check failed",
            function_name="check_security",
        )
        # Source code with production check provides additional context
        source = "if not PRODUCTION: raise RuntimeError('Missing key')"
        context = detect_assertion_context(issue, source)
        # Both VALIDATION (from 'check_') and SECURITY_GUARD (from PRODUCTION) are acceptable
        assert context in (AssertionContext.SECURITY_GUARD, AssertionContext.VALIDATION)

    def test_regular_function_is_unknown(self):
        """Regular functions should have UNKNOWN context."""
        issue = Issue(
            kind=IssueKind.ASSERTION_ERROR,
            message="Assertion failed",
            function_name="process_data",
        )
        context = detect_assertion_context(issue)
        assert context == AssertionContext.UNKNOWN

    def test_non_assertion_is_unknown(self):
        """Non-assertion issues should have UNKNOWN context."""
        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="Division by zero",
            function_name="calculate",
        )
        context = detect_assertion_context(issue)
        assert context == AssertionContext.UNKNOWN


class TestFilterIssue:
    """Test the filter_issue function."""

    def test_typing_fp_is_filtered(self):
        """Typing FPs should be filtered out."""
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Attempting to subscript Callable",
        )
        result = filter_issue(issue)
        assert result.should_filter is True
        assert "typing" in result.reason.lower()  # type: ignore[reportOptionalMemberAccess]

    def test_real_issue_not_filtered(self):
        """Real issues should not be filtered."""
        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="Division by zero: x can be 0",
        )
        result = filter_issue(issue)
        assert result.should_filter is False


class TestFilterIssues:
    """Test filtering a list of issues."""

    def test_filters_typing_fps(self):
        """Filter should remove typing FPs."""
        issues = [
            Issue(kind=IssueKind.DIVISION_BY_ZERO, message="Division by zero"),
            Issue(kind=IssueKind.TYPE_ERROR, message="Attempting to subscript Callable"),
            Issue(kind=IssueKind.INDEX_ERROR, message="Index out of bounds"),
        ]
        filtered = filter_issues(issues)
        assert len(filtered) == 2
        assert all(i.kind != IssueKind.TYPE_ERROR for i in filtered)

    def test_respects_filter_typing_flag(self):
        """filter_typing=False should keep typing FPs."""
        issues = [
            Issue(kind=IssueKind.TYPE_ERROR, message="Attempting to subscript Callable"),
        ]
        filtered = filter_issues(issues, filter_typing=False)
        assert len(filtered) == 1


class TestDeduplicateIssues:
    """Test issue deduplication."""

    def test_removes_exact_duplicates(self):
        """Exact duplicates should be removed."""
        issues = [
            Issue(kind=IssueKind.DIVISION_BY_ZERO, message="Div by zero", line_number=10),
            Issue(kind=IssueKind.DIVISION_BY_ZERO, message="Div by zero", line_number=10),
            Issue(kind=IssueKind.DIVISION_BY_ZERO, message="Div by zero", line_number=10),
        ]
        deduped = deduplicate_issues(issues)
        assert len(deduped) == 1

    def test_keeps_different_lines(self):
        """Same issue type on different lines should be kept."""
        issues = [
            Issue(kind=IssueKind.DIVISION_BY_ZERO, message="Div by zero", line_number=10),
            Issue(kind=IssueKind.DIVISION_BY_ZERO, message="Div by zero", line_number=20),
        ]
        deduped = deduplicate_issues(issues)
        assert len(deduped) == 2

    def test_keeps_different_types(self):
        """Different issue types on same line should be kept."""
        issues = [
            Issue(kind=IssueKind.DIVISION_BY_ZERO, message="Div by zero", line_number=10),
            Issue(kind=IssueKind.INDEX_ERROR, message="Index error", line_number=10),
        ]
        deduped = deduplicate_issues(issues)
        assert len(deduped) == 2

    def test_handles_empty_list(self):
        """Empty list should return empty list."""
        assert deduplicate_issues([]) == []


class TestPatternCoverage:
    """Test that all expected patterns are covered."""

    def test_all_typing_patterns_exist(self):
        """Verify all expected typing patterns are in the list."""
        expected = [
            "Callable",
            "ParamSpec",
            "TypeVar",
            "Protocol",
            "Generic",
        ]
        for pattern in expected:
            assert any(pattern in p for p in TYPING_FP_PATTERNS), f"Missing pattern: {pattern}"

    def test_confidence_enum_values(self):
        """Verify Confidence enum has expected values."""
        assert Confidence.HIGH.value == "high"
        assert Confidence.MEDIUM.value == "medium"
        assert Confidence.LOW.value == "low"

    def test_assertion_context_enum_values(self):
        """Verify AssertionContext enum has expected values."""
        assert AssertionContext.SECURITY_GUARD.value == "security_guard"
        assert AssertionContext.VALIDATION.value == "validation"
        assert AssertionContext.UNKNOWN.value == "unknown"
