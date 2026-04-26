from __future__ import annotations

from pathlib import Path

from pysymex.scanner.types import ScanResult, ScanResultBuilder, ScanSession


def test_scan_result_to_dict_serializes_non_primitives() -> None:
    result = ScanResult(
        file_path="a.py",
        timestamp="now",
        issues=[{"kind": "X", "detail": {"k": object()}}],
        code_objects=2,
        paths_explored=3,
    )
    data = result.to_dict()
    assert data["file"] == "a.py"
    assert isinstance(data["issues"], list)
    assert data["code_objects"] == 2


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
