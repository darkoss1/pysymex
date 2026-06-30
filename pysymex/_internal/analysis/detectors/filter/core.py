# pysymex: python symbolic execution & formal verification
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

"""False-positive issue filtering."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.analysis.detectors.filter.env import filters_disabled
from pysymex._internal.analysis.detectors.filter.patterns import (
    INTENTIONAL_ASSERTION_PATTERNS,
    TYPING_FP_PATTERNS,
)
from pysymex._internal.analysis.detectors.filter.types import (
    AssertionContext,
    Confidence,
    FilterIssueLike,
    FilterResult,
    TIssue,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

_CONFIDENCE_SCORES: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.5,
    Confidence.LOW: 0.25,
}


def is_typing_false_positive(issue: FilterIssueLike) -> bool:
    """Check if issue is a known typing-related false positive."""
    message = issue.message
    return any(pattern in message for pattern in TYPING_FP_PATTERNS)


def is_type_checking_block_issue(issue: FilterIssueLike) -> bool:
    """Check if issue comes from a TYPE_CHECKING block."""
    message = issue.message.lower()
    return "type_checking" in message or "typing." in message


def detect_assertion_context(
    issue: FilterIssueLike,
    source_code: str | None = None,
) -> AssertionContext:
    """Determine the context of an assertion-related issue."""
    from pysymex._internal.analysis.detectors.detector.types import IssueKind

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


def filter_issue(issue: FilterIssueLike, source_code: str | None = None) -> FilterResult:
    """Apply all filters to an issue and determine if it should be reported."""
    from pysymex._internal.analysis.detectors.filter.confidence import calculate_confidence

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


def _apply_filter_confidence(issue: TIssue, confidence: Confidence) -> TIssue:
    """Lower default canonical issue confidence when filter evidence requires it."""
    if not isinstance(issue, Issue):
        return issue
    if issue.model is None:
        return issue
    if issue.confidence < 1.0:
        return issue

    score = _CONFIDENCE_SCORES[confidence]
    if score >= issue.confidence:
        return issue
    return cast("TIssue", dataclasses.replace(issue, confidence=score))


def filter_issues(
    issues: Sequence[TIssue],
    filter_typing: bool = True,
    filter_intentional: bool = True,
    min_confidence: Confidence = Confidence.LOW,
    source_code: str | None = None,
) -> list[TIssue]:
    """Filter a list of issues based on configured criteria."""
    if filters_disabled():
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

        filtered.append(_apply_filter_confidence(issue, result.confidence))

    return filtered
