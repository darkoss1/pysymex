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

"""CI/CD type definitions for pysymex."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum

from pysymex.reporting.sarif import Severity


class ExitCode(IntEnum):
    """Standard exit codes for CI pipelines.

    Values 0–5 cover general outcomes; 10–13 encode the highest
    severity found.
    """

    SUCCESS = 0
    ISSUES_FOUND = 1
    ERROR = 2
    CONFIG_ERROR = 3
    FILE_NOT_FOUND = 4
    TIMEOUT = 5
    CRITICAL_FOUND = 10
    HIGH_FOUND = 11
    MEDIUM_FOUND = 12
    LOW_FOUND = 13


_SEVERITY_EXIT_CODES: dict[Severity, ExitCode] = {
    Severity.CRITICAL: ExitCode.CRITICAL_FOUND,
    Severity.HIGH: ExitCode.HIGH_FOUND,
    Severity.MEDIUM: ExitCode.MEDIUM_FOUND,
    Severity.LOW: ExitCode.LOW_FOUND,
    Severity.INFO: ExitCode.ISSUES_FOUND,
}

_HIGH_ISSUE_KINDS = frozenset(
    {
        "ASSERTION_ERROR",
        "ATTRIBUTE_ERROR",
        "CONTRACT_VIOLATION",
        "DIVISION_BY_ZERO",
        "FORMAT_STRING_INJECTION",
        "INDEX_ERROR",
        "INJECTION",
        "KEY_ERROR",
        "MODULO_BY_ZERO",
        "NAME_ERROR",
        "NULL_DEREFERENCE",
        "OVERFLOW",
        "OVERFLOW_ERROR",
        "RECURSION_LIMIT",
        "RESOURCE_LEAK",
        "RUNTIME_ERROR",
        "TYPE_ERROR",
        "UNBOUND_LOCAL",
        "UNBOUND_VARIABLE",
        "UNHANDLED_EXCEPTION",
        "VALUE_ERROR",
    }
)


def issue_kind(issue: Mapping[str, object]) -> str:
    """Return the stable CI kind/type label for a scanner issue."""
    raw_kind = issue.get("type") or issue.get("kind") or "analysis_issue"
    return str(raw_kind)


def issue_message(issue: Mapping[str, object]) -> str:
    """Return the human-readable scanner issue message."""
    raw_message = issue.get("message") or issue.get("description") or f"Issue: {issue_kind(issue)}"
    return str(raw_message)


def issue_file(issue: Mapping[str, object]) -> str:
    """Return the best available issue file path."""
    raw_file = issue.get("file") or issue.get("filename") or "unknown"
    return str(raw_file)


def issue_line(issue: Mapping[str, object]) -> int:
    """Return a positive 1-based issue line number."""
    for key in ("line", "line_number"):
        raw_line = issue.get(key)
        try:
            if isinstance(raw_line, bool):
                continue
            if isinstance(raw_line, int | str):
                line = int(raw_line)
                return max(1, line)
        except (TypeError, ValueError):
            continue
    return 1


def _severity_name(value: object) -> str | None:
    """Normalize enum-like and string-like severity values to uppercase names."""
    if isinstance(value, Severity):
        return value.name
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name.upper()
    if isinstance(value, str):
        return value.upper().replace("-", "_").replace(" ", "_")
    return None


def issue_severity(issue: Mapping[str, object]) -> Severity:
    """Map scanner issue dictionaries to CI/SARIF severities."""
    severity_name = _severity_name(issue.get("severity"))
    if severity_name in {"CRITICAL", "FATAL"}:
        return Severity.CRITICAL
    if severity_name in {"HIGH", "ERROR"}:
        return Severity.HIGH
    if severity_name in {"MEDIUM", "WARNING", "WARN"}:
        return Severity.MEDIUM
    if severity_name in {"LOW", "HINT"}:
        return Severity.LOW
    if severity_name in {"INFO", "INFORMATIONAL", "NOTE"}:
        return Severity.INFO

    kind_name = issue_kind(issue).upper().replace("-", "_").replace(" ", "_")
    if "CRITICAL" in kind_name:
        return Severity.CRITICAL
    if kind_name in _HIGH_ISSUE_KINDS or kind_name.endswith("_ERROR"):
        return Severity.HIGH
    return Severity.MEDIUM


@dataclass(frozen=True, slots=True)
class CIResult:
    """Result of a CI analysis run.

    Attributes:
        exit_code: Overall outcome.
        issues_count: Total issue count across all severities.
        critical_count: Number of critical-severity issues.
        high_count: Number of high-severity issues.
        medium_count: Number of medium-severity issues.
        low_count: Number of low-severity issues.
        info_count: Number of informational issues.
        files_analyzed: Number of files scanned.
        duration_seconds: Wall-clock analysis time.
        sarif_path: Path to the generated SARIF file, if any.
        message: Human-readable summary.
    """

    exit_code: ExitCode
    issues_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    files_analyzed: int = 0
    duration_seconds: float = 0.0
    sarif_path: str | None = None
    message: str = ""

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "exit_code": self.exit_code.value,
            "exit_code_name": self.exit_code.name,
            "issues_count": self.issues_count,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "files_analyzed": self.files_analyzed,
            "duration_seconds": self.duration_seconds,
            "sarif_path": self.sarif_path,
            "message": self.message,
        }

    def to_json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass(frozen=True, slots=True)
class FailureThreshold:
    """Configures when a CI run should fail.

    The default thresholds treat any *critical* or *high* issue as a
    failure while ignoring *medium* / *low* counts.

    Attributes:
        min_severity: Minimum severity that triggers a failure.
        max_critical: Maximum allowed critical issues (``-1`` = unlimited).
        max_high: Maximum allowed high issues (``-1`` = unlimited).
        max_medium: Maximum allowed medium issues (``-1`` = unlimited).
        max_low: Maximum allowed low issues (``-1`` = unlimited).
        max_total: Maximum allowed total issues (``-1`` = unlimited).
    """

    min_severity: Severity = Severity.HIGH
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = -1
    max_low: int = -1
    max_info: int = -1
    max_total: int = -1

    def should_fail(self, result: CIResult) -> bool:
        """Check if the result should cause CI to fail."""
        if self.count_at_or_above(result, self.min_severity) > 0:
            return True
        if self.max_critical >= 0 and result.critical_count > self.max_critical:
            return True
        if self.max_high >= 0 and result.high_count > self.max_high:
            return True
        if self.max_medium >= 0 and result.medium_count > self.max_medium:
            return True
        if self.max_low >= 0 and result.low_count > self.max_low:
            return True
        if self.max_info >= 0 and result.info_count > self.max_info:
            return True
        if self.max_total >= 0 and result.issues_count > self.max_total:
            return True
        return False

    def count_at_or_above(self, result: CIResult, severity: Severity) -> int:
        """Count findings that meet or exceed *severity*."""
        if severity == Severity.CRITICAL:
            return result.critical_count
        if severity == Severity.HIGH:
            return result.critical_count + result.high_count
        if severity == Severity.MEDIUM:
            return result.critical_count + result.high_count + result.medium_count
        if severity == Severity.LOW:
            return (
                result.critical_count + result.high_count + result.medium_count + result.low_count
            )
        return result.issues_count

    def get_exit_code(self, result: CIResult) -> ExitCode:
        """Get the appropriate exit code for the result."""
        for severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ):
            if self.count_for_severity(result, severity) > 0:
                return _SEVERITY_EXIT_CODES[severity]
        return ExitCode.SUCCESS

    def count_for_severity(self, result: CIResult, severity: Severity) -> int:
        """Count findings with exactly *severity*."""
        if severity == Severity.CRITICAL:
            return result.critical_count
        if severity == Severity.HIGH:
            return result.high_count
        if severity == Severity.MEDIUM:
            return result.medium_count
        if severity == Severity.LOW:
            return result.low_count
        return result.info_count
