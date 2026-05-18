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

"""Base protocol for scan report formatters."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence


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
    }


class Formatter(Protocol):
    """Protocol that all CLI formatters must implement."""

    def format_static(
        self,
        issues: Sequence[Any],
        total: int,
        suppressed: int,
        duration: float,
    ) -> str:
        """Format static analysis results."""
        ...

    def format_pipeline(
        self,
        results: Mapping[str, Any],
        all_issues: list[tuple[str, Any]],
        total: int,
        duration: float,
    ) -> str:
        """Format pipeline analysis results."""
        ...

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
