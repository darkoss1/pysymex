"""Models for the Docker-based multi-version test runner."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TestStatus(Enum):
    """Status of test execution."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True, slots=True)
class TestResult:
    """Result of test execution for a single Python version."""

    version: str
    container_name: str
    status: TestStatus
    exit_code: int | None
    duration: float
    passed: int
    failed: int
    errors: int
    skipped: int
    xfailed: int
    xpassed: int
    total: int
    output: str
    error_output: str
