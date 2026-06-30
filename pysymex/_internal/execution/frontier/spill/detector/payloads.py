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

"""Detector-sidecar spill encoding."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.execution.detectors.records import DeferredDetectorIssue
from pysymex._internal.execution.frontier.spill.fields.decode import is_json_value

if TYPE_CHECKING:
    from pysymex._internal.core.outcome import IssueKind
    from pysymex._internal.core.state.deferred import DeferredStateIssue
    from pysymex._internal.execution.frontier.spill.values.types import JsonObject, JsonValue


def detector_issues_payload(
    deferred_issues: tuple[DeferredStateIssue, ...],
) -> list[JsonValue] | None:
    """Return spill-safe detector sidecars or ``None`` when evidence is unsupported."""
    encoded: list[JsonValue] = []
    for deferred in deferred_issues:
        payload = _deferred_detector_payload(deferred)
        if payload is None:
            return None
        encoded.append(payload)
    return encoded


def _deferred_detector_payload(deferred: DeferredStateIssue) -> JsonObject | None:
    if type(deferred) is not DeferredDetectorIssue:
        return None
    issue_payload = _issue_payload(deferred.issue)
    site_key_payload = _site_key_payload(deferred.site_key)
    if issue_payload is None or site_key_payload is None:
        return None
    return {
        "kind": "deferred_detector_issue",
        "issue": issue_payload,
        "site_key": site_key_payload,
    }


def _issue_payload(issue: Issue) -> JsonObject | None:
    if type(issue) is not Issue:
        return None
    if issue.constraints or issue.model is not None:
        return None
    counterexample = _json_value(issue.counterexample)
    if isinstance(counterexample, _UnsupportedSentinel):
        return None
    return {
        "kind": issue.kind.name,
        "message": issue.message,
        "pc": issue.pc,
        "line_number": issue.line_number,
        "function_name": issue.function_name,
        "filename": issue.filename,
        "stack_trace": list(issue.stack_trace),
        "class_name": issue.class_name,
        "full_path": issue.full_path,
        "counterexample": counterexample,
        "is_caught": issue.is_caught,
        "confidence": issue.confidence,
        "likelihood": issue.likelihood,
        "severity": issue.severity.name if issue.severity is not None else None,
        "file": issue.file,
        "line": issue.line,
        "column": issue.column,
        "explanation": issue.explanation,
        "related_code": issue.related_code,
        "fix_suggestion": issue.fix_suggestion,
        "detector_name": issue.detector_name,
        "suppression_reason": issue.suppression_reason,
    }


def _site_key_payload(site_key: tuple[int, int, IssueKind]) -> list[JsonValue] | None:
    instruction_list_id, pc, kind = site_key
    if isinstance(instruction_list_id, bool) or isinstance(pc, bool):
        return None
    return [instruction_list_id, pc, kind.name]


def _json_value(value: object) -> JsonValue | _UnsupportedSentinel:
    if is_json_value(value):
        return cast("JsonValue", value)
    return _UNSUPPORTED


class _UnsupportedSentinel:
    """Sentinel for detector sidecars that must remain live."""


_UNSUPPORTED = _UnsupportedSentinel()
