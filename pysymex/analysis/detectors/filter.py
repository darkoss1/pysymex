# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""False Positive Filter for pysymex.

This module provides filtering mechanisms to reduce false positives from:
- Type annotation constructs (Callable, ParamSpec, TypeVar, etc.)
- TYPE_CHECKING blocks
- Intentional assertions (security guards, validation)
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import re
import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, TypeGuard, TypeVar

from pysymex._typing import is_list_of_objects


class IssueLike(Protocol):
    @property
    def kind(self) -> object: ...

    @property
    def message(self) -> str: ...

    @property
    def function_name(self) -> str | None: ...

    @property
    def model(self) -> object | None: ...

    @property
    def line_number(self) -> int | None: ...

    @property
    def pc(self) -> int: ...


TIssue = TypeVar("TIssue", bound=IssueLike)


def _filters_disabled() -> bool:
    """Return True when issue filtering/deduplication must be bypassed."""
    return os.getenv("PYSYMEX_DISABLE_FP_FILTER", "0") in {"1", "true", "TRUE"}


class _DeclLike(Protocol):
    """Small protocol for Z3 model declarations."""

    def name(self) -> str: ...


def _is_decl_list(value: object) -> TypeGuard[list[_DeclLike]]:
    """Return whether a value is a list of declaration-like objects."""
    if not is_list_of_objects(value):
        return False
    for item in value:
        name_attr = getattr(item, "name", None)
        if not callable(name_attr):
            return False
    return True


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


def is_typing_false_positive(issue: IssueLike) -> bool:
    """Check if issue is a known typing-related false positive.

    Args:
        issue: The issue to check

    Returns:
        True if this is likely a typing-related FP
    """
    message = issue.message
    return any(pattern in message for pattern in TYPING_FP_PATTERNS)


def is_type_checking_block_issue(issue: IssueLike) -> bool:
    """Check if issue comes from a TYPE_CHECKING block.

    Args:
        issue: The issue to check

    Returns:
        True if this issue is from TYPE_CHECKING block
    """
    message = issue.message.lower()
    return "type_checking" in message or "typing." in message


def detect_assertion_context(
    issue: IssueLike,
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
    if any(word in message_lower for word in ("validate", "sanitize", "check", "verify", "ensure")):
        return AssertionContext.VALIDATION

    if issue.function_name:
        func_lower = issue.function_name.lower()
        if any(
            word in func_lower
            for word in ("validate", "sanitize", "check", "verify", "ensure", "guard")
        ):
            return AssertionContext.VALIDATION

        if any(word in func_lower for word in ("security", "auth", "permission")):
            return AssertionContext.SECURITY_GUARD

    if source_code:
        for pattern in INTENTIONAL_ASSERTION_PATTERNS:
            if pattern.search(source_code):
                return AssertionContext.SECURITY_GUARD

    return AssertionContext.UNKNOWN


def _model_involves_havoc(issue: IssueLike) -> bool:
    """Return True if the issue's Z3 counter-example uses havoc variables."""
    if issue.model is None:
        return False
    try:
        decls_fn = getattr(issue.model, "decls", None)
        if not callable(decls_fn):
            return False
        decls = decls_fn()
        if not _is_decl_list(decls):
            return False
        for decl in decls:
            if decl.name().startswith("havoc_"):
                return True
    except Exception:
        pass
    return False


def calculate_confidence(issue: IssueLike) -> Confidence:
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


def filter_issue(issue: IssueLike, source_code: str | None = None) -> FilterResult:
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
    issues: Sequence[TIssue],
    filter_typing: bool = True,
    filter_intentional: bool = True,
    min_confidence: Confidence = Confidence.LOW,
    source_code: str | None = None,
) -> list[TIssue]:
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
    if _filters_disabled():
        return list(issues)

    confidence_order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    min_idx = confidence_order.index(min_confidence)

    filtered: list[TIssue] = []
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


from collections import defaultdict
import dataclasses

ISSUE_PRIORITIES: dict[str, int] = {
    "NULL_DEREFERENCE": 100,
    "ATTRIBUTE_ERROR": 80,
    "KEY_ERROR": 70,
    "TYPE_ERROR": 50,
    "DIVISION_BY_ZERO": 40,
    "INDEX_ERROR": 40,
    "ASSERTION_ERROR": 30,
}

NULL_FAMILY = frozenset({"NULL_DEREFERENCE", "ATTRIBUTE_ERROR", "TYPE_ERROR"})


def _get_kind_str(kind: object) -> str:
    """Safely convert an issue kind (Enum or otherwise) to a string."""
    return str(kind.name) if isinstance(kind, Enum) else str(kind)


def _get_issue_rank(issue: IssueLike) -> tuple[int, float, int]:
    """Rank issues for selection: Priority > Confidence > Message Simplicity."""
    kind_str = _get_kind_str(issue.kind)
    priority = ISSUE_PRIORITIES.get(kind_str, 0)
    confidence = getattr(issue, "confidence", 0.0)
    return (priority, confidence, -len(issue.message))


def _get_message_skeleton(msg: str) -> str:
    """Generate a structural skeleton by masking numeric constants and signs.

    This allows 'x + 2' and 'x - 2' to share the same skeleton 'x ? #'.
    """
    skeleton = re.sub(r"\d+", "#", msg)
    skeleton = re.sub(r"[+-]\s*#", "? #", skeleton)
    return skeleton


def _merge_variants(variants: list[TIssue]) -> TIssue:
    """Select the best variant and intelligently append a structural note if needed."""
    best = max(variants, key=_get_issue_rank)
    if len(variants) <= 1:
        return best

    messages = [v.message for v in variants]
    has_plus = any("+" in m for m in messages)
    has_minus = any("-" in m for m in messages)

    variant_note = f" (+ {len(variants) - 1} similar path variations)"

    if has_plus and has_minus and len(variants) == 2:
        s1, s2 = messages[0], messages[1]
        if len(s1) == len(s2):
            diffs = [i for i in range(len(s1)) if s1[i] != s2[i]]
            if len(diffs) == 1 and s1[diffs[0]] in "+-" and s2[diffs[0]] in "+-":
                variant_note = " (Detected in both '+' and '-' path variations)"

    if dataclasses.is_dataclass(best):
        try:
            return dataclasses.replace(best, message=best.message + variant_note)
        except Exception:
            pass

    return best


def deduplicate_issues(issues: Sequence[TIssue]) -> list[TIssue]:
    """Remove duplicate issues and unify structurally similar variants.

    This filter ensures that each unique bug site (PC + line) only reports
    the most relevant issue. It groups paths by structural skeletons to
    unify variations (e.g. +2 vs -2) and suppresses lesser bugs if multiple
    related errors (like NULL and ATTR) occur at the exact same location.
    """
    if _filters_disabled():
        return list(issues)

    variant_groups: dict[tuple[int | None, int, str, str], list[TIssue]] = defaultdict(list)

    for issue in issues:
        kind_str = _get_kind_str(issue.kind)
        skel = _get_message_skeleton(issue.message)

        bucket_key = (issue.line_number, issue.pc, kind_str, skel)
        variant_groups[bucket_key].append(issue)

    merged_variants = [_merge_variants(group) for group in variant_groups.values()]

    family_buckets: dict[tuple[int | None, int, str], TIssue] = {}

    for issue in merged_variants:
        kind_str = _get_kind_str(issue.kind)

        family = "NULL_FAMILY" if kind_str in NULL_FAMILY else kind_str
        family_key = (issue.line_number, issue.pc, family)

        if family_key not in family_buckets:
            family_buckets[family_key] = issue
        elif _get_issue_rank(issue) > _get_issue_rank(family_buckets[family_key]):
            family_buckets[family_key] = issue

    return sorted(family_buckets.values(), key=lambda x: (x.line_number or 0, x.pc))
