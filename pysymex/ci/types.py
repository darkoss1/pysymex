"""CI/CD type definitions for pysymex."""

from __future__ import annotations

import json
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
    max_total: int = -1

    def should_fail(self, result: CIResult) -> bool:
        """Check if the result should cause CI to fail."""
        if self.min_severity == Severity.CRITICAL and result.critical_count > 0:
            return True
        if self.min_severity == Severity.HIGH and (result.critical_count + result.high_count) > 0:
            return True
        if (
            self.min_severity == Severity.MEDIUM
            and (result.critical_count + result.high_count + result.medium_count) > 0
        ):
            return True
        if self.min_severity == Severity.LOW and result.issues_count > 0:
            return True
        if self.max_critical >= 0 and result.critical_count > self.max_critical:
            return True
        if self.max_high >= 0 and result.high_count > self.max_high:
            return True
        if self.max_medium >= 0 and result.medium_count > self.max_medium:
            return True
        if self.max_low >= 0 and result.low_count > self.max_low:
            return True
        if self.max_total >= 0 and result.issues_count > self.max_total:
            return True
        return False

    def get_exit_code(self, result: CIResult) -> ExitCode:
        """Get the appropriate exit code for the result."""
        if result.critical_count > 0:
            return ExitCode.CRITICAL_FOUND
        if result.high_count > 0:
            return ExitCode.HIGH_FOUND
        if result.medium_count > 0:
            return ExitCode.MEDIUM_FOUND
        if result.low_count > 0:
            return ExitCode.LOW_FOUND
        return ExitCode.SUCCESS


__all__ = [
    "CIResult",
    "ExitCode",
    "FailureThreshold",
]
