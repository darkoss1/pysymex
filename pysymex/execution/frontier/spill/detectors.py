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

"""Detector-sidecar encoding for frontier spill payloads."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import TypeVar, cast

from pysymex.analysis.detectors import Issue, IssueKind, Severity
from pysymex.core.state.deferred import DeferredStateIssue
from pysymex.execution.detectors import DeferredDetectorIssue
from pysymex.execution.frontier.spill.values import JsonObject, JsonValue

_EnumT = TypeVar("_EnumT", bound=Enum)

__all__ = [
    "SpillDetectorDecodeError",
    "decode_detector_issues",
    "detector_issues_payload",
]


class SpillDetectorDecodeError(ValueError):
    """Raised when a detector-sidecar spill payload is malformed."""


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


def decode_detector_issues(raw_issues: object) -> list[DeferredStateIssue]:
    """Decode detector sidecars from a spill payload."""
    if raw_issues is None:
        return []
    if not isinstance(raw_issues, list):
        raise SpillDetectorDecodeError("deferred detector issues must be a list")
    return [_decode_deferred_detector(raw_issue) for raw_issue in cast("list[object]", raw_issues)]


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


def _decode_deferred_detector(raw_issue: object) -> DeferredDetectorIssue:
    payload = _object_payload(raw_issue)
    if payload is None or payload.get("kind") != "deferred_detector_issue":
        raise SpillDetectorDecodeError("deferred detector issue is malformed")
    issue = _decode_issue(payload.get("issue"))
    site_key = _decode_site_key(payload.get("site_key"))
    return DeferredDetectorIssue(issue, site_key)


def _decode_issue(raw_issue: object) -> Issue:
    payload = _object_payload(raw_issue)
    if payload is None:
        raise SpillDetectorDecodeError("detector issue payload is malformed")
    return Issue(
        kind=_issue_kind(payload, "kind"),
        message=_required_str(payload, "message"),
        pc=_required_int(payload, "pc"),
        line_number=_optional_int(payload, "line_number"),
        function_name=_optional_str(payload, "function_name"),
        filename=_optional_str(payload, "filename"),
        stack_trace=_str_tuple(payload, "stack_trace"),
        class_name=_optional_str(payload, "class_name"),
        full_path=_optional_str(payload, "full_path"),
        counterexample=_optional_counterexample(payload, "counterexample"),
        is_caught=_required_bool(payload, "is_caught"),
        confidence=_required_float(payload, "confidence"),
        likelihood=_required_float(payload, "likelihood"),
        severity=_optional_severity(payload, "severity"),
        file=_required_str(payload, "file"),
        line=_required_int(payload, "line"),
        column=_optional_int(payload, "column"),
        explanation=_optional_str(payload, "explanation"),
        related_code=_optional_str(payload, "related_code"),
        fix_suggestion=_optional_str(payload, "fix_suggestion"),
        detector_name=_optional_str(payload, "detector_name"),
        suppression_reason=_optional_str(payload, "suppression_reason"),
    )


def _decode_site_key(raw_site_key: object) -> tuple[int, int, IssueKind]:
    if not isinstance(raw_site_key, list):
        raise SpillDetectorDecodeError("detector site key is malformed")
    items = cast("list[object]", raw_site_key)
    if len(items) != 3:
        raise SpillDetectorDecodeError("detector site key is malformed")
    instruction_list_id, pc, raw_kind = items
    if isinstance(instruction_list_id, bool) or not isinstance(instruction_list_id, int):
        raise SpillDetectorDecodeError("detector site key is malformed")
    if isinstance(pc, bool) or not isinstance(pc, int):
        raise SpillDetectorDecodeError("detector site key is malformed")
    if not isinstance(raw_kind, str):
        raise SpillDetectorDecodeError("detector site key is malformed")
    return (instruction_list_id, pc, _enum_member(IssueKind, raw_kind))


def _object_payload(raw_payload: object) -> Mapping[str, object] | None:
    if not isinstance(raw_payload, Mapping):
        return None
    raw_mapping = cast("Mapping[object, object]", raw_payload)
    result: dict[str, object] = {}
    for key, value in raw_mapping.items():
        if not isinstance(key, str):
            return None
        result[key] = value
    return result


def _issue_kind(payload: Mapping[str, object], key: str) -> IssueKind:
    return _enum_member(IssueKind, _required_str(payload, key))


def _optional_severity(payload: Mapping[str, object], key: str) -> Severity | None:
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        raise SpillDetectorDecodeError("detector issue severity is malformed")
    return _enum_member(Severity, raw_value)


def _enum_member(enum_type: type[_EnumT], name: str) -> _EnumT:
    try:
        return enum_type[name]
    except KeyError as exc:
        raise SpillDetectorDecodeError("detector enum value is unsupported") from exc


def _required_str(payload: Mapping[str, object], key: str) -> str:
    raw_value = payload.get(key)
    if isinstance(raw_value, str):
        return raw_value
    raise SpillDetectorDecodeError(f"detector issue field {key!r} must be a string")


def _optional_str(payload: Mapping[str, object], key: str) -> str | None:
    raw_value = payload.get(key)
    if raw_value is None or isinstance(raw_value, str):
        return raw_value
    raise SpillDetectorDecodeError(f"detector issue field {key!r} must be a string or null")


def _required_int(payload: Mapping[str, object], key: str) -> int:
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        raise SpillDetectorDecodeError(f"detector issue field {key!r} must be an integer")
    if isinstance(raw_value, int):
        return raw_value
    raise SpillDetectorDecodeError(f"detector issue field {key!r} must be an integer")


def _optional_int(payload: Mapping[str, object], key: str) -> int | None:
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        raise SpillDetectorDecodeError(f"detector issue field {key!r} must be an integer")
    if isinstance(raw_value, int):
        return raw_value
    raise SpillDetectorDecodeError(f"detector issue field {key!r} must be an integer or null")


def _required_bool(payload: Mapping[str, object], key: str) -> bool:
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        return raw_value
    raise SpillDetectorDecodeError(f"detector issue field {key!r} must be a bool")


def _required_float(payload: Mapping[str, object], key: str) -> float:
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        raise SpillDetectorDecodeError(f"detector issue field {key!r} must be a number")
    if isinstance(raw_value, (int, float)):
        return float(raw_value)
    raise SpillDetectorDecodeError(f"detector issue field {key!r} must be a number")


def _str_tuple(payload: Mapping[str, object], key: str) -> tuple[str, ...]:
    raw_value = payload.get(key)
    if not isinstance(raw_value, list):
        raise SpillDetectorDecodeError(f"detector issue field {key!r} must be a list")
    values: list[str] = []
    for item in cast("list[object]", raw_value):
        if not isinstance(item, str):
            raise SpillDetectorDecodeError(f"detector issue field {key!r} must contain strings")
        values.append(item)
    return tuple(values)


def _optional_counterexample(
    payload: Mapping[str, object],
    key: str,
) -> dict[str, object] | None:
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if not isinstance(raw_value, dict):
        raise SpillDetectorDecodeError("detector issue counterexample is malformed")
    raw_mapping = cast("dict[object, object]", raw_value)
    if not _is_json_value(raw_mapping):
        raise SpillDetectorDecodeError("detector issue counterexample is malformed")
    return {cast("str", item_key): item_value for item_key, item_value in raw_mapping.items()}


def _json_value(value: object) -> JsonValue | "_UnsupportedSentinel":
    if _is_json_value(value):
        return cast("JsonValue", value)
    return _UNSUPPORTED


def _is_json_value(value: object) -> bool:
    if isinstance(value, (bool, int, float, str)) or value is None:
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in cast("list[object]", value))
    if isinstance(value, dict):
        raw_mapping = cast("dict[object, object]", value)
        return all(
            isinstance(key, str) and _is_json_value(item) for key, item in raw_mapping.items()
        )
    return False


class _UnsupportedSentinel:
    """Sentinel for detector sidecars that must remain live."""


_UNSUPPORTED = _UnsupportedSentinel()
