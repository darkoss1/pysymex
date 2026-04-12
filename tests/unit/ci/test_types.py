from __future__ import annotations

import json

from pysymex.ci.types import CIResult, ExitCode, FailureThreshold
from pysymex.reporting.sarif import Severity


def test_ci_result_to_dict_and_json() -> None:
    result = CIResult(
        exit_code=ExitCode.HIGH_FOUND,
        issues_count=3,
        high_count=2,
        low_count=1,
        files_analyzed=4,
        duration_seconds=1.25,
        sarif_path="out.sarif",
        message="failed",
    )

    data = result.to_dict()
    assert data["exit_code"] == ExitCode.HIGH_FOUND.value
    assert data["exit_code_name"] == "HIGH_FOUND"
    assert data["by_severity"] == {"critical": 0, "high": 2, "medium": 0, "low": 1}

    payload = json.loads(result.to_json())
    assert payload["files_analyzed"] == 4
    assert payload["sarif_path"] == "out.sarif"


def test_failure_threshold_should_fail_and_exit_code() -> None:
    threshold = FailureThreshold(min_severity=Severity.HIGH, max_total=5)
    passing = CIResult(exit_code=ExitCode.SUCCESS, issues_count=0)
    failing = CIResult(
        exit_code=ExitCode.SUCCESS,
        issues_count=1,
        high_count=1,
    )

    assert threshold.should_fail(passing) is False
    assert threshold.should_fail(failing) is True
    assert threshold.get_exit_code(failing) is ExitCode.HIGH_FOUND

