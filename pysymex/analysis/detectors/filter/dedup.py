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

"""Deduplicate and rank detected issues by location, severity, and confidence."""

from __future__ import annotations

import dataclasses
import re
from collections import defaultdict
from collections.abc import Sequence
from enum import Enum
from typing import cast

from pysymex.analysis.detectors.filter.env import filters_disabled
from pysymex.analysis.detectors.filter.types import IssueLike, TIssue
from pysymex.logger import get_logger

logger = get_logger(__name__)

ISSUE_PRIORITIES: dict[str, int] = {
    "NULL_DEREFERENCE": 100,
    "ATTRIBUTE_ERROR": 80,
    "UNBOUND_VARIABLE": 75,
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


def _has_trigger_evidence(issue: IssueLike) -> bool:
    """Return whether an issue can show concrete trigger assignments."""
    get_counterexample = getattr(issue, "get_counterexample", None)
    if callable(get_counterexample):
        counterexample: object = get_counterexample()
    else:
        counterexample = getattr(issue, "counterexample", None)
    if not isinstance(counterexample, dict):
        return False
    return len(cast("dict[object, object]", counterexample)) > 0


def _get_issue_rank(issue: IssueLike) -> tuple[int, int, float, int]:
    """Rank issues for selection: priority, trigger evidence, confidence, simplicity."""
    kind_str = _get_kind_str(issue.kind)
    priority = ISSUE_PRIORITIES.get(kind_str, 0)
    trigger_rank = 1 if _has_trigger_evidence(issue) else 0
    confidence = getattr(issue, "confidence", 0.0)
    return (priority, trigger_rank, confidence, -len(issue.message))


def _get_message_skeleton(msg: str) -> str:
    """Generate a structural skeleton by masking numeric constants and signs."""
    skeleton = re.sub(r"\d+", "#", msg)
    skeleton = re.sub(r"[+-]\s*#", "? #", skeleton)
    return skeleton


def _merge_variants(variants: list[TIssue]) -> TIssue:
    """Select the best variant and append a structural note if needed."""
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
            logger.debug("Failed to annotate deduplicated dataclass issue variant", exc_info=True)

    return best


def deduplicate_issues(issues: Sequence[TIssue]) -> list[TIssue]:
    """Remove duplicate issues and unify structurally similar variants."""
    if filters_disabled():
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

    deduped = list(family_buckets.values())
    unbound_lines = {
        (issue.line_number, getattr(issue, "function_name", None))
        for issue in deduped
        if _get_kind_str(issue.kind) == "UNBOUND_VARIABLE"
    }
    if unbound_lines:
        deduped = [
            issue
            for issue in deduped
            if _get_kind_str(issue.kind) != "TYPE_ERROR"
            or (issue.line_number, getattr(issue, "function_name", None)) not in unbound_lines
        ]

    unbound_groups: dict[tuple[int | None, str | None, str], list[TIssue]] = defaultdict(list)
    passthrough: list[TIssue] = []
    for issue in deduped:
        if _get_kind_str(issue.kind) != "UNBOUND_VARIABLE":
            passthrough.append(issue)
            continue
        key = (issue.line_number, getattr(issue, "function_name", None), issue.message)
        unbound_groups[key].append(issue)

    deduped = [*passthrough, *(_merge_variants(group) for group in unbound_groups.values())]

    return sorted(deduped, key=lambda x: (x.line_number or 0, x.pc))


__all__ = [
    "ISSUE_PRIORITIES",
    "NULL_FAMILY",
    "deduplicate_issues",
]
