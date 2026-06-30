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

"""Evidence-first report projections for contract verification."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum
from typing import cast

from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import EvidenceResult
from pysymex._internal.contracts.reports.adapters import extract_counterexample_from_model

EVIDENCE_REPORT_SCHEMA = "pysymex.contracts.evidence.v1"


def contract_evidence_to_dict(evidence: EvidenceResult) -> dict[str, object]:
    """Serialize one contract evidence record without changing its meaning."""
    obligation = evidence.obligation
    clause = obligation.clause
    target = clause.target
    counterexample = evidence.counterexample
    if not counterexample and evidence.model is not None:
        counterexample = extract_counterexample_from_model(evidence.model)
    return {
        "obligation_id": [_jsonable_token(part) for part in obligation.obligation_id],
        "clause_id": [_jsonable_token(part) for part in clause.clause_id],
        "target": {
            "name": target.name,
            "qualname": target.qualname,
            "module": target.module,
        },
        "frontend": clause.frontend,
        "kind": evidence.kind.name,
        "hook": obligation.hook.value,
        "query_kind": obligation.query_kind.value,
        "pc": obligation.pc,
        "condition": evidence.condition,
        "message": evidence.message,
        "status": evidence.status.name,
        "solver_status": evidence.solver_status.value,
        "severity": evidence.severity.name,
        "line_number": evidence.line_number,
        "unsupported_reasons": [reason.value for reason in evidence.unsupported_reasons],
        "timeout_ms": evidence.timeout_ms,
        "need_model": evidence.need_model,
        "theory_profile": [feature.value for feature in evidence.theory_profile],
        "counterexample": _jsonable(counterexample),
    }


def contract_evidence_for_issue(issue: object) -> dict[str, object] | None:
    """Return serialized evidence attached to an issue-like object."""
    evidence = getattr(issue, "evidence", None)
    if not isinstance(evidence, EvidenceResult):
        return None
    return contract_evidence_to_dict(evidence)


def contract_evidence_for_result(result: object) -> list[dict[str, object]]:
    """Return deterministic evidence records for a verified result-like object."""
    evidence_records = list(_iter_result_evidence(result))
    evidence_records.sort(key=_evidence_sort_key)
    return [contract_evidence_to_dict(evidence) for evidence in evidence_records]


def not_verified_reasons_for_result(result: object) -> list[str]:
    """Return concise reasons a verified result should not be presented as proven."""
    reasons: list[str] = []
    for label in _object_sequence(result, "degraded_passes"):
        _append_unique(reasons, f"analysis_degraded:{label}")
    for evidence in _iter_result_evidence(result):
        if evidence.status is not VerificationResult.VERIFIED:
            _append_unique(reasons, _reason_for_status(evidence.status))
    for issue in _object_sequence(result, "contract_issues"):
        raw_result = getattr(issue, "result", None)
        if (
            isinstance(raw_result, VerificationResult)
            and raw_result is not VerificationResult.VERIFIED
        ):
            _append_unique(reasons, _reason_for_status(raw_result))
    return reasons


def verified_result_evidence_dict(result: object) -> dict[str, object]:
    """Serialize one verified execution result as an evidence-first report entry."""
    return {
        "function_name": str(getattr(result, "function_name", "")),
        "source_file": str(getattr(result, "source_file", "")),
        "summary": {
            "paths_explored": int(getattr(result, "paths_explored", 0)),
            "paths_completed": int(getattr(result, "paths_completed", 0)),
            "contracts_checked": int(getattr(result, "contracts_checked", 0)),
            "contracts_verified": int(getattr(result, "contracts_verified", 0)),
            "contracts_violated": int(getattr(result, "contracts_violated", 0)),
            "total_time_seconds": float(getattr(result, "total_time_seconds", 0.0)),
            "analysis_degraded": bool(_object_sequence(result, "degraded_passes")),
            "degraded_passes": list(_object_sequence(result, "degraded_passes")),
            "not_verified_reasons": not_verified_reasons_for_result(result),
        },
        "obligations": contract_evidence_for_result(result),
    }


def verified_results_evidence_report(
    results: Sequence[object],
    *,
    total: int,
    duration: float,
    pysymex_version: str,
) -> dict[str, object]:
    """Build the top-level JSON evidence report for verify output."""
    return {
        "pysymex_version": pysymex_version,
        "mode": "contracts",
        "evidence_schema": EVIDENCE_REPORT_SCHEMA,
        "functions_verified": len(results),
        "total_issues": total,
        "results": [verified_result_evidence_dict(result) for result in results],
        "duration": duration,
    }


def _iter_result_evidence(result: object) -> tuple[EvidenceResult, ...]:
    """Collect unique evidence records from result and issue containers."""
    seen: set[tuple[object, ...]] = set()
    records: list[EvidenceResult] = []
    for evidence in _object_sequence(result, "contract_evidence"):
        if isinstance(evidence, EvidenceResult):
            _append_evidence(records, seen, evidence)
    for issue in _object_sequence(result, "contract_issues"):
        evidence = getattr(issue, "evidence", None)
        if isinstance(evidence, EvidenceResult):
            _append_evidence(records, seen, evidence)
    return tuple(records)


def _append_evidence(
    records: list[EvidenceResult],
    seen: set[tuple[object, ...]],
    evidence: EvidenceResult,
) -> None:
    """Append evidence once by obligation identity."""
    key = evidence.obligation.obligation_id
    if key in seen:
        return
    seen.add(key)
    records.append(evidence)


def _evidence_sort_key(evidence: EvidenceResult) -> tuple[object, ...]:
    """Return a deterministic ordering key for report evidence."""
    target = evidence.obligation.clause.target
    return (
        target.module or "",
        target.qualname,
        evidence.line_number or 0,
        evidence.kind.name,
        evidence.obligation.hook.value,
        evidence.obligation.query_kind.value,
        tuple(str(part) for part in evidence.obligation.obligation_id),
    )


def _object_sequence(obj: object, attr: str) -> tuple[object, ...]:
    """Return an attribute as a safe object tuple."""
    raw = getattr(obj, attr, ())
    if isinstance(raw, (str, bytes, bytearray)):
        return ()
    if isinstance(raw, Sequence):
        return tuple(cast("Sequence[object]", raw))
    return ()


def _reason_for_status(status: VerificationResult) -> str:
    """Return a concise not-verified reason for a contract status."""
    if status is VerificationResult.VIOLATED:
        return "contract_violated"
    if status is VerificationResult.UNSUPPORTED:
        return "contract_unsupported"
    if status is VerificationResult.UNKNOWN:
        return "contract_unknown"
    if status is VerificationResult.UNREACHABLE:
        return "contract_unreachable"
    return f"contract_{status.name.lower()}"


def _append_unique(values: list[str], value: str) -> None:
    """Append a value only once while preserving discovery order."""
    if value not in values:
        values.append(value)


def _jsonable_token(value: object) -> object:
    """Normalize identity tuple parts for JSON output."""
    if isinstance(value, Enum):
        return value.name
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _jsonable(value: object) -> object:
    """Return a JSON-compatible version of report metadata."""
    if isinstance(value, Enum):
        return value.name
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        return {str(key): _jsonable(item) for key, item in mapping.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        sequence = cast("Sequence[object]", value)
        return [_jsonable(item) for item in sequence]
    return str(value)
