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

"""Public result, outcome, and summary helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from enum import Enum
from typing import cast

from pysymex._internal.core.outcome import AnalysisOutcome, OutcomeEvidence, OutcomeSubreason
from pysymex._internal.execution.executors.verified.types import VerifiedExecutionResult
from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.execution.termination import TerminationProof, TerminationStatus
from pysymex._internal.scanner.types import ScanResult

def data(value: object) -> dict[str, object]:
    """Serialize a public workflow result into a JSON-friendly dictionary."""
    if _is_scan_result_sequence(value):
        scan_results = cast("Sequence[ScanResult]", value)
        return {
            "kind": "scan_results",
            "summary": _scan_summary(scan_results),
            "results": [item.to_dict() for item in scan_results],
        }
    if isinstance(value, VerifiedExecutionResult):
        return _verified_result_to_dict(value)
    to_dict_method = getattr(value, "to_dict", None)
    if callable(to_dict_method):
        raw = to_dict_method()
        if isinstance(raw, Mapping):
            return _mapping_to_dict(cast("Mapping[object, object]", raw))
    return {
        "kind": type(value).__name__,
        "repr": repr(value),
    }


def count(value: object) -> int:
    """Return the total finding count across a public workflow result."""
    if _is_scan_result_sequence(value):
        return sum(count(item) for item in cast("Sequence[ScanResult]", value))
    return (
        len(getattr(value, "issues", []) or [])
        + len(getattr(value, "contract_issues", []) or [])
        + len(getattr(value, "arithmetic_issues", []) or [])
    )


def degraded(value: object) -> bool:
    """Return whether a result contains degraded or partial analysis evidence."""
    if _is_scan_result_sequence(value):
        return any(degraded(item) for item in cast("Sequence[ScanResult]", value))
    degraded_passes = getattr(value, "degraded_passes", []) or []
    if degraded_passes:
        return True
    return bool(getattr(value, "error", None))


def clean(value: object) -> bool:
    """Return whether a result has no findings, errors, or degraded passes."""
    if _is_scan_result_sequence(value):
        return all(clean(item) for item in cast("Sequence[ScanResult]", value))
    if isinstance(value, VerifiedExecutionResult):
        return value.is_verified
    return count(value) == 0 and not degraded(value)


def _verified_result_to_dict(result: VerifiedExecutionResult) -> dict[str, object]:
    """Serialize a verified-execution result without requiring an internal formatter."""
    return {
        "kind": "verified_execution",
        "function_name": result.function_name,
        "source_file": result.source_file,
        "is_verified": result.is_verified,
        "has_issues": result.has_issues,
        "paths_explored": result.paths_explored,
        "paths_completed": result.paths_completed,
        "paths_pruned": result.paths_pruned,
        "coverage_instructions": len(result.coverage),
        "total_time_seconds": result.total_time_seconds,
        "issues": [_issue_to_dict(issue) for issue in result.issues],
        "contract_issues": [_issue_to_dict(issue) for issue in result.contract_issues],
        "contracts_checked": result.contracts_checked,
        "contracts_verified": result.contracts_verified,
        "contracts_violated": result.contracts_violated,
        "arithmetic_issues": [_issue_to_dict(issue) for issue in result.arithmetic_issues],
        "termination_proof": _serialize(result.termination_proof),
        "inferred_properties": [_serialize(prop) for prop in result.inferred_properties],
        "degraded_passes": list(result.degraded_passes),
    }


def _scan_summary(results: Sequence[ScanResult]) -> dict[str, int]:
    """Return aggregate scan counters for a sequence of scan results."""
    return {
        "files": len(results),
        "total_issues": sum(len(result.issues) for result in results),
        "files_with_issues": sum(1 for result in results if result.issues),
        "errors": sum(1 for result in results if result.error),
        "degraded": sum(1 for result in results if result.degraded_passes),
    }


def _is_scan_result_sequence(value: object) -> bool:
    """Return whether *value* is a non-string sequence of scan results."""
    if isinstance(value, (str, bytes, bytearray)):
        return False
    if not isinstance(value, Sequence):
        return False
    return all(isinstance(item, ScanResult) for item in cast("Sequence[object]", value))


def _issue_to_dict(issue: object) -> dict[str, object]:
    """Serialize an issue-like value using the public issue helper."""
    from pysymex._internal.api.issues import data

    return data(issue)


def _serialize(value: object) -> object:
    """Convert common result fields into JSON-friendly values."""
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, Mapping):
        return _mapping_to_dict(cast("Mapping[object, object]", value))
    if isinstance(value, (list, tuple)):
        return [_serialize(item) for item in cast("Iterable[object]", value)]
    if isinstance(value, (set, frozenset)):
        return sorted((_serialize(item) for item in cast("Iterable[object]", value)), key=repr)
    to_dict_method = getattr(value, "to_dict", None)
    if callable(to_dict_method):
        raw = to_dict_method()
        if isinstance(raw, Mapping):
            return _mapping_to_dict(cast("Mapping[object, object]", raw))
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    return str(value)


def _mapping_to_dict(mapping: Mapping[object, object]) -> dict[str, object]:
    """Serialize a mapping with string keys."""
    return {str(key): _serialize(value) for key, value in mapping.items()}


__all__ = [
    "AnalysisOutcome",
    "ExecutionResult",
    "OutcomeEvidence",
    "OutcomeSubreason",
    "ScanResult",
    "TerminationProof",
    "TerminationStatus",
    "VerifiedExecutionResult",
    "clean",
    "count",
    "data",
    "degraded",
]
