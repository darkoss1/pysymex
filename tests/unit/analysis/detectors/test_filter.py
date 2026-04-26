from pysymex.analysis.detectors.filter import (
    Confidence,
    AssertionContext,
    FilterResult,
    is_typing_false_positive,
    is_type_checking_block_issue,
    detect_assertion_context,
    calculate_confidence,
    filter_issue,
    filter_issues,
    deduplicate_issues,
)
from pysymex.analysis.detectors.base import IssueKind


class MockIssue:
    def __init__(
        self,
        kind: IssueKind,
        message: str,
        function_name: str | None = None,
        model: object | None = None,
        line_number: int | None = None,
        pc: int = 0,
    ) -> None:
        self._kind = kind
        self._message = message
        self._function_name = function_name
        self._model = model
        self._line_number = line_number
        self._pc = pc

    @property
    def kind(self) -> IssueKind:
        return self._kind

    @property
    def message(self) -> str:
        return self._message

    @property
    def function_name(self) -> str | None:
        return self._function_name

    @property
    def model(self) -> object | None:
        return self._model

    @property
    def line_number(self) -> int | None:
        return self._line_number

    @property
    def pc(self) -> int:
        return self._pc


class TestIssueLike:
    """Test suite for pysymex.analysis.detectors.filter.IssueLike."""

    def test_kind(self) -> None:
        """Test kind behavior."""
        issue = MockIssue(IssueKind.UNKNOWN, "msg")
        assert issue.kind.name == "UNKNOWN"

    def test_message(self) -> None:
        """Test message behavior."""
        issue = MockIssue(IssueKind.UNKNOWN, "msg")
        assert issue.message == "msg"

    def test_function_name(self) -> None:
        """Test function_name behavior."""
        issue = MockIssue(IssueKind.UNKNOWN, "msg", function_name="f")
        assert issue.function_name == "f"

    def test_model(self) -> None:
        """Test model behavior."""
        issue = MockIssue(IssueKind.UNKNOWN, "msg", model={})
        assert issue.model == {}

    def test_line_number(self) -> None:
        """Test line_number behavior."""
        issue = MockIssue(IssueKind.UNKNOWN, "msg", line_number=10)
        assert issue.line_number == 10

    def test_pc(self) -> None:
        """Test pc behavior."""
        issue = MockIssue(IssueKind.UNKNOWN, "msg", pc=5)
        assert issue.pc == 5


class TestConfidence:
    """Test suite for pysymex.analysis.detectors.filter.Confidence."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert Confidence.HIGH.value == "high"


class TestAssertionContext:
    """Test suite for pysymex.analysis.detectors.filter.AssertionContext."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert AssertionContext.UNKNOWN.value == "unknown"


class TestFilterResult:
    """Test suite for pysymex.analysis.detectors.filter.FilterResult."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        res = FilterResult(should_filter=True, reason="r")
        assert res.should_filter is True
        assert res.reason == "r"
        assert res.confidence == Confidence.HIGH


def test_is_typing_false_positive() -> None:
    """Test is_typing_false_positive behavior."""
    assert (
        is_typing_false_positive(MockIssue(IssueKind.UNKNOWN, "Attempting to subscript Callable"))
        is True
    )
    assert is_typing_false_positive(MockIssue(IssueKind.UNKNOWN, "Normal error")) is False


def test_is_type_checking_block_issue() -> None:
    """Test is_type_checking_block_issue behavior."""
    assert (
        is_type_checking_block_issue(MockIssue(IssueKind.UNKNOWN, "in TYPE_CHECKING block")) is True
    )
    assert is_type_checking_block_issue(MockIssue(IssueKind.UNKNOWN, "in regular code")) is False


def test_detect_assertion_context() -> None:
    """Test detect_assertion_context behavior."""
    issue1 = MockIssue(IssueKind.ASSERTION_ERROR, "Please validate input")
    assert detect_assertion_context(issue1) == AssertionContext.VALIDATION

    issue2 = MockIssue(IssueKind.ASSERTION_ERROR, "Failed", function_name="check_auth")
    assert detect_assertion_context(issue2) == AssertionContext.VALIDATION

    issue3 = MockIssue(IssueKind.UNKNOWN, "Failed")
    assert detect_assertion_context(issue3) == AssertionContext.UNKNOWN


def test_calculate_confidence() -> None:
    """Test calculate_confidence behavior."""
    issue_high = MockIssue(IssueKind.DIVISION_BY_ZERO, "msg", model={})
    assert calculate_confidence(issue_high) == Confidence.HIGH

    issue_abstract = MockIssue(IssueKind.UNKNOWN, "[Abstract Interpreter] error")
    assert calculate_confidence(issue_abstract) == Confidence.HIGH

    issue_assert = MockIssue(IssueKind.ASSERTION_ERROR, "fail")
    assert calculate_confidence(issue_assert) == Confidence.MEDIUM

    issue_type = MockIssue(IssueKind.TYPE_ERROR, "Attempting to subscript Callable")
    assert calculate_confidence(issue_type) == Confidence.LOW


def test_filter_issue() -> None:
    """Test filter_issue behavior."""
    issue_typing = MockIssue(IssueKind.TYPE_ERROR, "Attempting to subscript Callable")
    res1 = filter_issue(issue_typing)
    assert res1.should_filter is True
    assert res1.reason == "Typing annotation false positive"

    issue_valid = MockIssue(IssueKind.DIVISION_BY_ZERO, "msg", model={})
    res2 = filter_issue(issue_valid)
    assert res2.should_filter is False
    assert res2.confidence == Confidence.HIGH


def test_filter_issues() -> None:
    """Test filter_issues behavior."""
    issues = [
        MockIssue(IssueKind.TYPE_ERROR, "Attempting to subscript Callable"),
        MockIssue(IssueKind.DIVISION_BY_ZERO, "msg", model={}),
    ]
    filtered = filter_issues(issues)
    assert len(filtered) == 1
    assert filtered[0].kind == IssueKind.DIVISION_BY_ZERO


def test_deduplicate_issues() -> None:
    """Test deduplicate_issues behavior."""
    issues = [
        MockIssue(IssueKind.DIVISION_BY_ZERO, "msg", line_number=10, pc=5),
        MockIssue(IssueKind.DIVISION_BY_ZERO, "msg", line_number=10, pc=5),
        MockIssue(IssueKind.TYPE_ERROR, "msg", line_number=10, pc=5),
    ]
    dedup = deduplicate_issues(issues)
    assert len(dedup) == 2
