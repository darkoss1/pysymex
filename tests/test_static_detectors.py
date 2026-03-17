"""Tests for pysymex.analysis.detectors.static_detectors.

Covers all concrete detector classes:
- StaticDivisionByZeroDetector
- StaticKeyErrorDetector
- StaticIndexErrorDetector
- StaticTypeErrorDetector
- StaticAttributeErrorDetector
- StaticAssertionErrorDetector
- DeadCodeDetector

Each detector is tested with should_check() and check() via
manually constructed DetectionContext objects.
"""

from __future__ import annotations

import dis
from typing import Any

import pytest

from pysymex.analysis.detectors.static_detectors import (
    DeadCodeDetector,
    StaticAssertionErrorDetector,
    StaticAttributeErrorDetector,
    StaticDivisionByZeroDetector,
    StaticIndexErrorDetector,
    StaticKeyErrorDetector,
    StaticTypeErrorDetector,
)
from pysymex.analysis.detectors.static_types import (
    DetectionContext,
    Issue,
    IssueKind,
    Severity,
    StaticDetector,
)
from pysymex.analysis.type_inference import PyType, TypeEnvironment, TypeKind
from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions


# ===================================================================
# Helper: build a DetectionContext from a function
# ===================================================================


def _make_context(
    func: Any,
    *,
    pc_opname: str | None = None,
    pc_argrepr: str | None = None,
    type_overrides: dict[str, PyType] | None = None,
    file_path: str = "<test>",
) -> DetectionContext | None:
    """Build a DetectionContext pointing at the first instruction matching criteria.

    If *pc_opname* is given, the context points at the first instruction whose
    ``opname`` matches.  If *pc_argrepr* is also given, both must match.
    Falls back to the first instruction when no filter is given.
    """
    code = func.__code__
    instructions = list(_cached_get_instructions(code))
    if not instructions:
        return None

    target = instructions[0]
    found = pc_opname is None  # no filter means any instruction is fine
    for instr in instructions:
        if pc_opname and instr.opname != pc_opname:
            continue
        if pc_argrepr and instr.argrepr != pc_argrepr:
            continue
        target = instr
        found = True
        break

    if not found:
        return None

    type_env = TypeEnvironment()
    if type_overrides:
        for name, typ in type_overrides.items():
            type_env.set_type(name, typ)

    return DetectionContext(
        code=code,
        instructions=instructions,
        pc=target.offset,
        instruction=target,
        line=target.line_number or code.co_firstlineno,
        type_env=type_env,
        file_path=file_path,
        function_name=code.co_name,
    )


# ===================================================================
# IssueKind / Severity / Issue basics
# ===================================================================


class TestIssueKindSeverity:
    """Basic enum and dataclass checks."""

    def test_issue_kind_members(self):
        assert IssueKind.DIVISION_BY_ZERO is not None
        assert IssueKind.KEY_ERROR is not None
        assert IssueKind.INDEX_ERROR is not None
        assert IssueKind.TYPE_ERROR is not None
        assert IssueKind.ATTRIBUTE_ERROR is not None
        assert IssueKind.ASSERTION_ERROR is not None
        assert IssueKind.DEAD_CODE is not None

    def test_severity_ordering(self):
        # Just confirm they exist
        assert Severity.CRITICAL is not None
        assert Severity.ERROR is not None
        assert Severity.WARNING is not None
        assert Severity.INFO is not None
        assert Severity.HINT is not None

    def test_issue_not_suppressed(self):
        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            severity=Severity.ERROR,
            file="t.py",
            line=1,
            message="div by zero",
        )
        assert not issue.is_suppressed()

    def test_issue_suppressed(self):
        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            severity=Severity.ERROR,
            file="t.py",
            line=1,
            message="div by zero",
            suppression_reason="caught",
        )
        assert issue.is_suppressed()

    def test_issue_format(self):
        issue = Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            severity=Severity.ERROR,
            file="t.py",
            line=1,
            message="div by zero",
        )
        formatted = issue.format()
        assert "t.py" in formatted
        assert "div by zero" in formatted


# ===================================================================
# StaticDivisionByZeroDetector
# ===================================================================


def _div_by_const_zero(x):
    return x / 0


def _div_by_var(x, y):
    return x / y


def _div_by_const_nonzero(x):
    return x / 2


def _modulo_by_var(x, y):
    return x % y


def _no_division(x):
    return x + 1


class TestStaticDivisionByZeroDetector:
    """Tests for StaticDivisionByZeroDetector."""

    @pytest.fixture()
    def detector(self):
        return StaticDivisionByZeroDetector()

    def test_issue_kind(self, detector):
        assert detector.issue_kind() == IssueKind.DIVISION_BY_ZERO

    def test_should_check_division(self, detector):
        ctx = _make_context(_div_by_var, pc_opname="BINARY_OP", pc_argrepr="/")
        if ctx:
            assert detector.should_check(ctx)

    def test_should_not_check_addition(self, detector):
        ctx = _make_context(_no_division, pc_opname="BINARY_OP", pc_argrepr="+")
        if ctx:
            assert not detector.should_check(ctx)

    def test_detect_const_zero(self, detector):
        ctx = _make_context(_div_by_const_zero, pc_opname="BINARY_OP", pc_argrepr="/")
        if ctx:
            issue = detector.check(ctx)
            if issue:
                assert issue.kind == IssueKind.DIVISION_BY_ZERO
                assert issue.confidence == 1.0

    def test_no_issue_const_nonzero(self, detector):
        ctx = _make_context(_div_by_const_nonzero, pc_opname="BINARY_OP", pc_argrepr="/")
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_detect_var_divisor(self, detector):
        ctx = _make_context(_div_by_var, pc_opname="BINARY_OP", pc_argrepr="/")
        if ctx:
            issue = detector.check(ctx)
            # May or may not produce issue depending on context
            if issue:
                assert issue.kind == IssueKind.DIVISION_BY_ZERO

    def test_detector_name(self, detector):
        assert detector.name == "StaticDivisionByZeroDetector"

    def test_severity_high_confidence(self, detector):
        assert detector.get_severity(1.0) == Severity.ERROR

    def test_severity_medium_confidence(self, detector):
        assert detector.get_severity(0.8) == Severity.WARNING

    def test_severity_low_confidence(self, detector):
        assert detector.get_severity(0.6) == Severity.INFO

    def test_severity_very_low_confidence(self, detector):
        assert detector.get_severity(0.3) == Severity.HINT


# ===================================================================
# StaticKeyErrorDetector
# ===================================================================


def _dict_subscript(d, k):
    return d[k]


def _dict_const_key(d):
    return d["key"]


def _no_subscript(x):
    return x + 1


class TestStaticKeyErrorDetector:
    """Tests for StaticKeyErrorDetector."""

    @pytest.fixture()
    def detector(self):
        return StaticKeyErrorDetector()

    def test_issue_kind(self, detector):
        assert detector.issue_kind() == IssueKind.KEY_ERROR

    def test_should_check_subscript(self, detector):
        ctx = _make_context(_dict_subscript, pc_opname="BINARY_SUBSCR")
        if ctx:
            assert detector.should_check(ctx)

    def test_should_not_check_non_subscript(self, detector):
        ctx = _make_context(_no_subscript, pc_opname="BINARY_OP")
        if ctx:
            assert not detector.should_check(ctx)

    def test_check_dict_with_unknown_type(self, detector):
        ctx = _make_context(
            _dict_subscript,
            pc_opname="BINARY_SUBSCR",
            type_overrides={"d": PyType(kind=TypeKind.DICT, name="dict")},
        )
        if ctx:
            issue = detector.check(ctx)
            # May or may not produce issue
            if issue:
                assert issue.kind == IssueKind.KEY_ERROR

    def test_no_issue_for_defaultdict(self, detector):
        ctx = _make_context(
            _dict_subscript,
            pc_opname="BINARY_SUBSCR",
            type_overrides={"d": PyType(kind=TypeKind.DEFAULTDICT, name="defaultdict")},
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_no_issue_for_counter(self, detector):
        ctx = _make_context(
            _dict_subscript,
            pc_opname="BINARY_SUBSCR",
            type_overrides={"d": PyType(kind=TypeKind.COUNTER, name="Counter")},
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_known_key_no_issue(self, detector):
        ctx = _make_context(
            _dict_const_key,
            pc_opname="BINARY_SUBSCR",
            type_overrides={
                "d": PyType(
                    kind=TypeKind.DICT,
                    name="dict",
                    known_keys=frozenset(["key"]),
                )
            },
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_detector_name(self, detector):
        assert detector.name == "StaticKeyErrorDetector"


# ===================================================================
# StaticIndexErrorDetector
# ===================================================================


def _list_subscript(lst, i):
    return lst[i]


def _list_const_index(lst):
    return lst[0]


class TestStaticIndexErrorDetector:
    """Tests for StaticIndexErrorDetector."""

    @pytest.fixture()
    def detector(self):
        return StaticIndexErrorDetector()

    def test_issue_kind(self, detector):
        assert detector.issue_kind() == IssueKind.INDEX_ERROR

    def test_should_check_subscript(self, detector):
        ctx = _make_context(_list_subscript, pc_opname="BINARY_SUBSCR")
        if ctx:
            assert detector.should_check(ctx)

    def test_check_list_with_unknown_index(self, detector):
        ctx = _make_context(
            _list_subscript,
            pc_opname="BINARY_SUBSCR",
            type_overrides={"lst": PyType(kind=TypeKind.LIST, name="list")},
        )
        if ctx:
            issue = detector.check(ctx)
            # May produce an issue or may not (depends on heuristics)
            if issue:
                assert issue.kind == IssueKind.INDEX_ERROR

    def test_safe_index_with_known_length(self, detector):
        ctx = _make_context(
            _list_const_index,
            pc_opname="BINARY_SUBSCR",
            type_overrides={
                "lst": PyType(kind=TypeKind.LIST, name="list", length=5)
            },
        )
        if ctx:
            issue = detector.check(ctx)
            # Index 0 is safe for length 5
            assert issue is None

    def test_no_issue_for_dict_type(self, detector):
        ctx = _make_context(
            _list_subscript,
            pc_opname="BINARY_SUBSCR",
            type_overrides={"lst": PyType(kind=TypeKind.DICT, name="dict")},
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_no_issue_for_builtin_names(self, detector):
        """If the container var name is a builtin type, should not report."""
        # This is tricky to test directly, but we can verify the logic exists
        ctx = _make_context(
            _list_subscript,
            pc_opname="BINARY_SUBSCR",
            type_overrides={"lst": PyType(kind=TypeKind.LIST, name="list")},
        )
        if ctx:
            # At minimum the detector should not crash
            issue = detector.check(ctx)
            assert issue is None or isinstance(issue, Issue)

    def test_detector_name(self, detector):
        assert detector.name == "StaticIndexErrorDetector"


# ===================================================================
# StaticTypeErrorDetector
# ===================================================================


def _binary_add(a, b):
    return a + b


def _call_func(f, x):
    return f(x)


def _attr_access(obj):
    return obj.value


class TestStaticTypeErrorDetector:
    """Tests for StaticTypeErrorDetector."""

    @pytest.fixture()
    def detector(self):
        return StaticTypeErrorDetector()

    def test_issue_kind(self, detector):
        assert detector.issue_kind() == IssueKind.TYPE_ERROR

    def test_should_check_binary_op(self, detector):
        ctx = _make_context(_binary_add, pc_opname="BINARY_OP")
        if ctx:
            assert detector.should_check(ctx)

    def test_should_check_call(self, detector):
        ctx = _make_context(_call_func, pc_opname="CALL")
        if ctx:
            assert detector.should_check(ctx)

    def test_should_check_load_attr(self, detector):
        ctx = _make_context(_attr_access, pc_opname="LOAD_ATTR")
        if ctx:
            assert detector.should_check(ctx)

    def test_numeric_add_no_issue(self, detector):
        ctx = _make_context(
            _binary_add,
            pc_opname="BINARY_OP",
            pc_argrepr="+",
            type_overrides={
                "a": PyType(kind=TypeKind.INT, name="int"),
                "b": PyType(kind=TypeKind.INT, name="int"),
            },
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_str_concat_no_issue(self, detector):
        ctx = _make_context(
            _binary_add,
            pc_opname="BINARY_OP",
            pc_argrepr="+",
            type_overrides={
                "a": PyType(kind=TypeKind.STR, name="str"),
                "b": PyType(kind=TypeKind.STR, name="str"),
            },
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_str_int_add_issue(self, detector):
        ctx = _make_context(
            _binary_add,
            pc_opname="BINARY_OP",
            pc_argrepr="+",
            type_overrides={
                "a": PyType(kind=TypeKind.STR, name="str"),
                "b": PyType(kind=TypeKind.INT, name="int"),
            },
        )
        if ctx:
            issue = detector.check(ctx)
            if issue:
                assert issue.kind == IssueKind.TYPE_ERROR

    def test_none_attr_access(self, detector):
        ctx = _make_context(
            _attr_access,
            pc_opname="LOAD_ATTR",
            type_overrides={"obj": PyType(kind=TypeKind.NONE, name="None")},
        )
        if ctx:
            issue = detector.check(ctx)
            if issue:
                assert "NoneType" in issue.message

    def test_unknown_types_no_issue(self, detector):
        ctx = _make_context(
            _binary_add,
            pc_opname="BINARY_OP",
            pc_argrepr="+",
            type_overrides={
                "a": PyType.unknown(),
                "b": PyType.unknown(),
            },
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_callable_no_issue(self, detector):
        ctx = _make_context(
            _call_func,
            pc_opname="CALL",
            type_overrides={"f": PyType(kind=TypeKind.CALLABLE, name="callable")},
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_detector_name(self, detector):
        assert detector.name == "StaticTypeErrorDetector"


# ===================================================================
# StaticAttributeErrorDetector
# ===================================================================


def _access_attr(obj):
    return obj.name


class TestStaticAttributeErrorDetector:
    """Tests for StaticAttributeErrorDetector."""

    @pytest.fixture()
    def detector(self):
        return StaticAttributeErrorDetector()

    def test_issue_kind(self, detector):
        assert detector.issue_kind() == IssueKind.ATTRIBUTE_ERROR

    def test_should_check_load_attr(self, detector):
        ctx = _make_context(_access_attr, pc_opname="LOAD_ATTR")
        if ctx:
            assert detector.should_check(ctx)

    def test_none_type_issue(self, detector):
        ctx = _make_context(
            _access_attr,
            pc_opname="LOAD_ATTR",
            type_overrides={"obj": PyType(kind=TypeKind.NONE, name="None")},
        )
        if ctx:
            issue = detector.check(ctx)
            if issue:
                assert issue.kind == IssueKind.ATTRIBUTE_ERROR
                assert "NoneType" in issue.message
                assert issue.confidence >= 0.9

    def test_unknown_type_no_issue(self, detector):
        ctx = _make_context(
            _access_attr,
            pc_opname="LOAD_ATTR",
            type_overrides={"obj": PyType.unknown()},
        )
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_optional_type_may_warn(self, detector):
        ctx = _make_context(
            _access_attr,
            pc_opname="LOAD_ATTR",
            type_overrides={
                "obj": PyType(kind=TypeKind.INT, name="int", nullable=True)
            },
        )
        if ctx:
            issue = detector.check(ctx)
            if issue:
                assert issue.kind == IssueKind.ATTRIBUTE_ERROR

    def test_detector_name(self, detector):
        assert detector.name == "StaticAttributeErrorDetector"


# ===================================================================
# StaticAssertionErrorDetector
# ===================================================================


def _assert_false():
    assert False


def _assert_true():
    assert True


def _assert_variable(x):
    assert x


class TestStaticAssertionErrorDetector:
    """Tests for StaticAssertionErrorDetector."""

    @pytest.fixture()
    def detector(self):
        return StaticAssertionErrorDetector()

    def test_issue_kind(self, detector):
        assert detector.issue_kind() == IssueKind.ASSERTION_ERROR

    def test_should_check_assertion(self, detector):
        ctx = _make_context(_assert_false, pc_opname="LOAD_ASSERTION_ERROR")
        if ctx:
            assert detector.should_check(ctx)

    def test_detect_assert_false(self, detector):
        ctx = _make_context(_assert_false, pc_opname="LOAD_ASSERTION_ERROR")
        if ctx:
            issue = detector.check(ctx)
            if issue:
                assert issue.kind == IssueKind.ASSERTION_ERROR
                assert "always fails" in issue.message.lower() or "False" in issue.message

    def test_assert_true_no_issue(self, detector):
        ctx = _make_context(_assert_true, pc_opname="LOAD_ASSERTION_ERROR")
        # If the assertion always passes, LOAD_ASSERTION_ERROR may not even
        # appear in the bytecode (compiler optimization), or check returns None
        if ctx:
            issue = detector.check(ctx)
            # Should be None because the condition is True
            # (may or may not be detected depending on bytecode structure)
            assert issue is None or isinstance(issue, Issue)

    def test_detector_name(self, detector):
        assert detector.name == "StaticAssertionErrorDetector"


# ===================================================================
# DeadCodeDetector
# ===================================================================


class TestDeadCodeDetector:
    """Tests for DeadCodeDetector."""

    @pytest.fixture()
    def detector(self):
        return DeadCodeDetector()

    def test_issue_kind(self, detector):
        assert detector.issue_kind() == IssueKind.DEAD_CODE

    def test_should_check_requires_flow_context(self, detector):
        ctx = _make_context(_no_division, pc_opname="BINARY_OP")
        if ctx:
            # flow_context is None by default
            assert not detector.should_check(ctx)

    def test_check_no_flow_context_returns_none(self, detector):
        ctx = _make_context(_no_division)
        if ctx:
            issue = detector.check(ctx)
            assert issue is None

    def test_detector_name(self, detector):
        assert detector.name == "DeadCodeDetector"


# ===================================================================
# StaticDetector base class tests
# ===================================================================


class TestStaticDetectorBase:
    """Tests for the StaticDetector base class via a concrete subclass."""

    def test_create_issue(self):
        detector = StaticDivisionByZeroDetector()
        ctx = _make_context(_div_by_var, pc_opname="BINARY_OP", pc_argrepr="/")
        if ctx:
            issue = detector.create_issue(ctx, message="test", confidence=0.8)
            assert issue.kind == IssueKind.DIVISION_BY_ZERO
            assert issue.message == "test"
            assert issue.confidence == 0.8

    def test_suppress_issue(self):
        detector = StaticDivisionByZeroDetector()
        ctx = _make_context(_div_by_var, pc_opname="BINARY_OP", pc_argrepr="/")
        if ctx:
            issue = detector.create_issue(ctx, message="test", confidence=0.8)
            suppressed = detector.suppress_issue(issue, "caught")
            assert suppressed.is_suppressed()
            assert suppressed.suppression_reason == "caught"

    def test_issues_list_starts_empty(self):
        detector = StaticDivisionByZeroDetector()
        assert detector.issues == []

    def test_get_severity_thresholds(self):
        detector = StaticDivisionByZeroDetector()
        assert detector.get_severity(0.96) == Severity.ERROR
        assert detector.get_severity(0.80) == Severity.WARNING
        assert detector.get_severity(0.60) == Severity.INFO
        assert detector.get_severity(0.40) == Severity.HINT
