"""False Positive Filter for pysymex.

This module provides filtering mechanisms to reduce false positives from:
- Type annotation constructs (Callable, ParamSpec, TypeVar, etc.)
- TYPE_CHECKING blocks
- Intentional assertions (security guards, validation)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.analysis.detectors import Issue


class Confidence(Enum):
    """Confidence level for a detected issue."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssertionContext(Enum):
    """Context for assertion-related issues."""

    SECURITY_GUARD = "security_guard"
    VALIDATION = "validation"
    INVARIANT = "invariant"
    ACCIDENTAL = "accidental"
    UNKNOWN = "unknown"


TYPING_FP_PATTERNS = [
    "Attempting to subscript import_Callable",
    "Attempting to subscript Callable",
    "Attempting to subscript ParamSpec",
    "Attempting to subscript TypeVar",
    "Attempting to subscript Protocol",
    "Attempting to subscript Generic",
    "Attempting to subscript Optional",
    "Attempting to subscript Union",
    "Attempting to subscript Literal",
    "Attempting to subscript Annotated",
    "Attempting to subscript ClassVar",
    "Attempting to subscript Final",
    "Attempting to subscript Type",
    "import_TYPE_CHECKING",
    "TYPE_CHECKING",
    "typing.",
    "typing_extensions.",
    "Index global_list",
    "Index global_dict",
    "Index global_tuple",
    "Index global_set",
    "Index global_frozenset",
    "Index global_type",
    "Index global_bytes",
    "Index global_str",
    "Index global_int",
    "Index global_float",
    "Index global_bool",
    "Index import_",
]

INTENTIONAL_ASSERTION_PATTERNS = [
    re.compile(r"if.*PRODUCTION", re.IGNORECASE),
    re.compile(r"if.*DEBUG", re.IGNORECASE),
    re.compile(r"if.*config\.", re.IGNORECASE),
    re.compile(r"if.*settings\.", re.IGNORECASE),
    re.compile(r"if.*ENV", re.IGNORECASE),
    re.compile(r"def\s+(validate|sanitize|check|verify|ensure|assert_)", re.IGNORECASE),
    re.compile(r"raise\s+ValueError\("),
    re.compile(r"raise\s+TypeError\("),
    re.compile(r"raise\s+RuntimeError\("),
    re.compile(r"raise\s+AssertionError\("),
    re.compile(r"if\s+not\s+\w+:\s*raise"),
    re.compile(r"if\s+\w+\s+is\s+None:\s*raise"),
    re.compile(r"assert\s+\w+\s+is\s+not\s+None"),
]

DICT_CONTAINER_PATTERNS = frozenset(
    {
        "dict",
        "map",
        "cache",
        "tracker",
        "store",
        "registry",
        "config",
        "settings",
        "lookup",
        "index",
        "table",
        "_recent",
        "_usage",
        "_count",
        "_limits",
    }
)


@dataclass(frozen=True, slots=True)
class FilterResult:
    """Result of applying filters to an issue."""

    should_filter: bool
    reason: str | None = None
    confidence: Confidence = Confidence.HIGH
    context: AssertionContext = AssertionContext.UNKNOWN


def is_typing_false_positive(issue: Issue) -> bool:
    """Check if issue is a known typing-related false positive.

    Args:
        issue: The issue to check

    Returns:
        True if this is likely a typing-related FP
    """
    message = issue.message
    return any(pattern in message for pattern in TYPING_FP_PATTERNS)


def is_type_checking_block_issue(issue: Issue) -> bool:
    """Check if issue comes from a TYPE_CHECKING block.

    Args:
        issue: The issue to check

    Returns:
        True if this issue is from TYPE_CHECKING block
    """
    message = issue.message.lower()
    return "type_checking" in message or "typing." in message


def detect_assertion_context(
    issue: Issue,
    source_code: str | None = None,
) -> AssertionContext:
    """Determine the context of an assertion-related issue.

    Args:
        issue: The issue to analyze
        source_code: Optional source code for context analysis

    Returns:
        The detected assertion context
    """
    from pysymex.analysis.detectors import IssueKind

    if issue.kind != IssueKind.ASSERTION_ERROR:
        return AssertionContext.UNKNOWN

    message_lower = issue.message.lower()
    if any(word in message_lower for word in ["validate", "sanitize", "check", "verify", "ensure"]):
        return AssertionContext.VALIDATION

    if issue.function_name:
        func_lower = issue.function_name.lower()
        if any(
            word in func_lower
            for word in ["validate", "sanitize", "check", "verify", "ensure", "guard"]
        ):
            return AssertionContext.VALIDATION

        if any(word in func_lower for word in ["security", "auth", "permission"]):
            return AssertionContext.SECURITY_GUARD

    if source_code:
        for pattern in INTENTIONAL_ASSERTION_PATTERNS:
            if pattern.search(source_code):
                return AssertionContext.SECURITY_GUARD

    return AssertionContext.UNKNOWN


def _model_involves_havoc(issue: Issue) -> bool:
    """Return True if the issue's Z3 counter-example uses havoc variables."""
    if issue.model is None:
        return False
    try:
        for decl in issue.model.decls():
            if decl.name().startswith("havoc_"):
                return True
    except Exception:
        pass
    return False


def calculate_confidence(issue: Issue) -> Confidence:
    """Calculate confidence level for an issue.

    Args:
        issue: The issue to evaluate

    Returns:
        Confidence level (HIGH, MEDIUM, LOW)
    """
    from pysymex.analysis.detectors import IssueKind

    havoc = _model_involves_havoc(issue)

    if issue.kind == IssueKind.DIVISION_BY_ZERO and issue.model is not None:
        return Confidence.MEDIUM if havoc else Confidence.HIGH

    if "[Abstract Interpreter]" in issue.message:
        return Confidence.HIGH

    if issue.kind == IssueKind.ASSERTION_ERROR:
        return Confidence.MEDIUM

    if issue.kind == IssueKind.TYPE_ERROR:
        if is_typing_false_positive(issue):
            return Confidence.LOW
        return Confidence.MEDIUM

    if issue.kind in (IssueKind.INDEX_ERROR, IssueKind.KEY_ERROR):
        if issue.model is not None:
            return Confidence.LOW if havoc else Confidence.MEDIUM
        return Confidence.LOW

    if issue.model is not None:
        return Confidence.LOW if havoc else Confidence.MEDIUM

    return Confidence.LOW


def filter_issue(issue: Issue, source_code: str | None = None) -> FilterResult:
    """Apply all filters to an issue and determine if it should be reported.

    Args:
        issue: The issue to filter
        source_code: Optional source code for context

    Returns:
        FilterResult with filtering decision and metadata
    """
    if is_typing_false_positive(issue):
        return FilterResult(
            should_filter=True,
            reason="Typing annotation false positive",
            confidence=Confidence.LOW,
        )

    if is_type_checking_block_issue(issue):
        return FilterResult(
            should_filter=True,
            reason="TYPE_CHECKING block issue",
            confidence=Confidence.LOW,
        )

    confidence = calculate_confidence(issue)
    context = detect_assertion_context(issue, source_code)

    if context in (AssertionContext.SECURITY_GUARD, AssertionContext.VALIDATION):
        return FilterResult(
            should_filter=True,
            reason=f"Intentional {context.value}",
            confidence=Confidence.LOW,
            context=context,
        )

    return FilterResult(
        should_filter=False,
        confidence=confidence,
        context=context,
    )


def filter_issues(
    issues: list[Issue],
    filter_typing: bool = True,
    filter_intentional: bool = True,
    min_confidence: Confidence = Confidence.LOW,
    source_code: str | None = None,
) -> list[Issue]:
    """Filter a list of issues based on configured criteria.

    Args:
        issues: List of issues to filter
        filter_typing: Filter typing-related FPs
        filter_intentional: Filter intentional assertions
        min_confidence: Minimum confidence to include
        source_code: Optional source code for context

    Returns:
        Filtered list of issues
    """
    confidence_order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    min_idx = confidence_order.index(min_confidence)

    filtered: list[Issue] = []
    for issue in issues:
        result = filter_issue(issue, source_code)

        if result.should_filter:
            if filter_typing and (
                "typing" in (result.reason or "").lower()
                or "type_checking" in (result.reason or "").lower()
            ):
                continue
            if filter_intentional and result.context in (
                AssertionContext.SECURITY_GUARD,
                AssertionContext.VALIDATION,
            ):
                continue

        issue_conf_idx = confidence_order.index(result.confidence)
        if issue_conf_idx < min_idx:
            continue

        filtered.append(issue)

    return filtered


def deduplicate_issues(issues: list[Issue]) -> list[Issue]:
    """Remove duplicate issues based on location and type.

    Args:
        issues: List of issues to deduplicate

    Returns:
        List with duplicates removed
    """
    seen: set[tuple[object, ...]] = set()
    result: list[Issue] = []

    for issue in issues:
        message_key = hash(issue.message) if issue.message else 0
        key = (
            issue.kind,
            issue.line_number,
            issue.pc,
            message_key,
        )
        if key not in seen:
            seen.add(key)
            result.append(issue)

    return result
