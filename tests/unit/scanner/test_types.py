from __future__ import annotations

from pathlib import Path

import pytest

from pysymex.scanner.session import session_var
from pysymex.scanner.summary import print_final_summary
from pysymex.scanner.types import ScanResult, ScanResultBuilder, ScanSession


def test_scan_result_to_dict_serializes_non_primitives() -> None:
    result = ScanResult(
        file_path="a.py",
        timestamp="now",
        issues=[{"kind": "X", "detail": {"k": object()}}],
        code_objects=2,
        paths_explored=3,
        degraded_passes=["solver_unknown_detector_query"],
    )
    data = result.to_dict()
    assert data["file"] == "a.py"
    assert isinstance(data["issues"], list)
    assert data["code_objects"] == 2
    assert data["degraded_passes"] == ["solver_unknown_detector_query"]


def test_scan_result_to_dict_sorts_unordered_issue_values() -> None:
    result = ScanResult(
        file_path="a.py",
        timestamp="now",
        issues=[{"values": {"gamma", "alpha", "beta"}}],
    )

    data = result.to_dict()

    assert data["issues"] == [{"values": ["alpha", "beta", "gamma"]}]


def test_scan_result_builder_chaining_and_build() -> None:
    built = (
        ScanResultBuilder(file_path="b.py", timestamp="t0")
        .add_issue({"kind": "WARN", "message": "m"})
        .add_paths(7)
        .set_error("boom")
        .build()
    )
    assert built.file_path == "b.py"
    assert built.paths_explored == 7
    assert built.error == "boom"


def test_scan_session_add_result_and_summary(tmp_path: Path) -> None:
    log_file = tmp_path / "scan-log.json"
    session = ScanSession(log_file=log_file)
    session.add_result(
        ScanResult(
            file_path="x.py",
            timestamp="t",
            issues=[{"kind": "TYPE_ERROR", "message": "bad"}],
        )
    )
    summary = session.get_summary()

    assert summary["files_scanned"] == 1
    assert summary["total_issues"] == 1
    assert summary["files_with_issues"] == 1
    assert log_file.exists()


def test_scan_session_does_not_count_degraded_result_as_clean(tmp_path: Path) -> None:
    session = ScanSession(log_file=tmp_path / "scan-log.json")
    session.add_result(
        ScanResult(
            file_path="x.py",
            timestamp="t",
            degraded_passes=["solver_unknown_detector_query"],
        )
    )

    summary = session.get_summary()

    assert summary["files_clean"] == 0
    assert summary["files_degraded"] == 1


def test_scan_session_reports_log_write_failure_in_plain_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log_directory = tmp_path / "not-a-log-file"
    log_directory.mkdir()
    session = ScanSession(log_file=log_directory)
    session.add_result(ScanResult(file_path="x.py", timestamp="t"))
    token = session_var.set(session)
    try:
        print_final_summary()
    finally:
        session_var.reset(token)

    assert session.log_write_error is not None
    output = capsys.readouterr().out
    assert "Log not saved to" in output
    assert "Log saved to" not in output
