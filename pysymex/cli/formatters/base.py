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

"""Base protocol for scan report formatters."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol, Sequence

from pysymex.contracts.reports.evidence import (
    contract_evidence_for_result,
    not_verified_reasons_for_result,
)


@dataclass(frozen=True)
class VerifyIssueRecord:
    """Normalized verification issue metadata for CLI formatter adapters."""

    issue: object
    issue_type: str
    message: str
    source_file: str
    function_name: str
    line_number: int | None


def format_verify_issue(issue: object) -> str:
    """Return a stable single-string representation of a verification issue."""
    format_fn = getattr(issue, "format", None)
    if callable(format_fn):
        return str(format_fn()).strip()
    return str(issue)


def verify_issue_count(result: object) -> int:
    """Count reportable verification findings on a result-like object."""
    return sum(
        len(getattr(result, attr, []))
        for attr in ("issues", "contract_issues", "arithmetic_issues")
    )


def _issue_line_number(issue: object) -> int | None:
    """Retrieve the line number attribute from an issue object if available.

    Args:
        issue (object): The issue object to inspect.

    Returns:
        int | None: The line number as an integer if found, otherwise None.
    """
    line_number = getattr(issue, "line_number", None)
    return line_number if isinstance(line_number, int) else None


def iter_verify_issue_records(result: object) -> Iterator[VerifyIssueRecord]:
    """Yield normalized verification issue records without choosing an output format."""
    source_file = str(getattr(result, "source_file", ""))
    function_name = str(getattr(result, "function_name", ""))
    for attr, default_type in (
        ("issues", "RUNTIME"),
        ("contract_issues", "CONTRACT"),
        ("arithmetic_issues", "ARITHMETIC"),
    ):
        for issue in getattr(result, attr, []):
            yield VerifyIssueRecord(
                issue=issue,
                issue_type=str(getattr(issue, "kind", default_type)),
                message=format_verify_issue(issue),
                source_file=source_file,
                function_name=function_name,
                line_number=_issue_line_number(issue),
            )


def verify_result_to_dict(result: object) -> dict[str, object]:
    """Serialize a verification result-like object for CLI formatters."""
    termination = None
    termination_proof = getattr(result, "termination_proof", None)
    if termination_proof is not None:
        status_obj = getattr(termination_proof, "status", None)
        status_name = getattr(status_obj, "name", None)
        termination = {
            "status": status_name if isinstance(status_name, str) else str(status_obj),
            "message": str(getattr(termination_proof, "message", "")),
        }

    contract_issues = list(getattr(result, "contract_issues", []))
    arithmetic_issues = list(getattr(result, "arithmetic_issues", []))
    runtime_issues = list(getattr(result, "issues", []))
    degraded_passes = list(getattr(result, "degraded_passes", []))
    contract_evidence = contract_evidence_for_result(result)

    return {
        "function_name": str(getattr(result, "function_name", "")),
        "source_file": str(getattr(result, "source_file", "")),
        "paths_explored": int(getattr(result, "paths_explored", 0)),
        "paths_completed": int(getattr(result, "paths_completed", 0)),
        "contracts_checked": int(getattr(result, "contracts_checked", 0)),
        "contracts_verified": int(getattr(result, "contracts_verified", 0)),
        "contracts_violated": int(getattr(result, "contracts_violated", 0)),
        "total_time_seconds": float(getattr(result, "total_time_seconds", 0.0)),
        "termination": termination,
        "runtime_issues": [format_verify_issue(issue) for issue in runtime_issues],
        "contract_issues": [format_verify_issue(issue) for issue in contract_issues],
        "arithmetic_issues": [format_verify_issue(issue) for issue in arithmetic_issues],
        "total_issues": verify_issue_count(result),
        "degraded_passes": degraded_passes,
        "analysis_degraded": bool(degraded_passes),
        "contract_evidence": contract_evidence,
        "not_verified_reasons": not_verified_reasons_for_result(result),
    }


class Formatter(Protocol):
    """Protocol that all CLI formatters must implement."""

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        """Format symbolic execution results."""
        ...

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        """Format contract verification results."""
        ...
