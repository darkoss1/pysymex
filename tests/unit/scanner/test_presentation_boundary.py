"""Scanner presentation boundary tests."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

import pysymex._internal.scanner.directory.sequential as sequential
from pysymex._internal.scanner.directory.scan import scan_directory
from pysymex._internal.scanner.file import scan_file
from pysymex._internal.scanner.types import ScanResult


class RecordingReporter:
    """Minimal reporter recording scanner presentation events."""

    def __init__(self) -> None:
        self.events: list[tuple[str, object]] = []

    def on_status(self, message: str) -> None:
        self.events.append(("status", message))

    def on_issue(self, issue: dict[str, object]) -> None:
        self.events.append(("issue", issue))

    def on_error(self, file_path: object, error: str) -> None:
        self.events.append(("error", (file_path, error)))

    def on_progress(
        self,
        completed: int,
        total: int,
        file_path: object,
        result: object | None,
    ) -> None:
        self.events.append(("progress", (completed, total, file_path, result)))

    def on_summary(self, results: Sequence[object], total_files: int) -> None:
        self.events.append(("summary", (len(results), total_files)))


def test_scan_file_verbose_without_reporter_is_silent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Single-file scanner must not print fallback errors without a reporter."""
    target = tmp_path / "broken.py"
    target.write_text("def broken(:\n", encoding="utf-8")

    result = scan_file(target, verbose=True, use_sandbox=False)

    captured = capsys.readouterr()
    assert result.error is not None
    assert result.error.startswith("Syntax Error:")
    assert captured.out == ""
    assert captured.err == ""


def test_scan_directory_verbose_without_reporter_is_silent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Directory scanner status remains silent when no reporter is supplied."""
    target = tmp_path / "target.py"
    target.write_text("x = 1\n", encoding="utf-8")
    scan_result = ScanResult(file_path=str(target), timestamp="now")

    def fake_scan_sequential(*args: object, **kwargs: object) -> list[ScanResult]:
        _ = args
        _ = kwargs
        return [scan_result]

    monkeypatch.setattr(
        "pysymex._internal.scanner.directory.scan._scan_sequential",
        fake_scan_sequential,
    )

    results = scan_directory(tmp_path, verbose=True, workers=1, use_sandbox=False)

    captured = capsys.readouterr()
    assert results == [scan_result]
    assert captured.out == ""
    assert captured.err == ""


def test_sequential_scan_uses_reporter_for_verbose_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verbose sequential scans route progress and summary through the reporter."""
    target = tmp_path / "target.py"
    target.write_text("x = 1\n", encoding="utf-8")
    reporter = RecordingReporter()
    scan_result = ScanResult(file_path=str(target), timestamp="now")

    def fake_scan_file(*args: object, **kwargs: object) -> ScanResult:
        _ = args
        assert kwargs["reporter"] is reporter
        return scan_result

    monkeypatch.setattr(sequential, "scan_file", fake_scan_file)

    results = sequential.scan_sequential_strategy(
        [target],
        verbose=True,
        max_paths=10,
        timeout=5.0,
        auto_tune=False,
        reporter=reporter,
        use_sandbox=False,
    )

    assert results == [scan_result]
    assert ("progress", (1, 1, target, scan_result)) in reporter.events
    assert ("summary", (1, 1)) in reporter.events


def test_scan_directory_requires_verbose_for_reporter_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reporter progress/status callbacks remain controlled by verbose mode."""
    target = tmp_path / "target.py"
    target.write_text("x = 1\n", encoding="utf-8")
    reporter = RecordingReporter()
    scan_result = ScanResult(file_path=str(target), timestamp="now")

    def fake_scan_sequential(*args: object, **kwargs: object) -> list[ScanResult]:
        _ = args
        _ = kwargs
        return [scan_result]

    monkeypatch.setattr(
        "pysymex._internal.scanner.directory.scan._scan_sequential",
        fake_scan_sequential,
    )

    results = scan_directory(
        tmp_path,
        verbose=False,
        workers=1,
        reporter=reporter,
        use_sandbox=False,
    )

    assert results == [scan_result]
    assert reporter.events == []
