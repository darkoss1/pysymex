"""CI/CD type definitions for pysymex."""

from __future__ import annotations


import json

from dataclasses import dataclass

from enum import IntEnum

from typing import Any


from pysymex.reporting.sarif import Severity


class ExitCode(IntEnum):
    """Standard exit codes for CI pipelines."""

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


@dataclass
class CIResult:
    """Result of CI analysis run."""

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

    def to_dict(self) -> dict[str, Any]:
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


@dataclass
class FailureThreshold:
    """Configures when CI should fail."""

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
    "ExitCode",
    "CIResult",
    "FailureThreshold",
]
