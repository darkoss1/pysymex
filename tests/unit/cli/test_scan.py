import argparse
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import pysymex._internal.stats.runtime as stats_runtime
from pysymex._internal.cli.commands.scan.command import cmd_scan, handle_symbolic_scan
from pysymex._internal.cli.commands.scan.shared import (
    format_scan_profile,
    publish_scan_stats_if_requested,
)
from pysymex._internal.scanner.types import ScanResult
from pysymex._internal.stats.types import EventType


def test_cmd_scan() -> None:
    """Test cmd_scan behavior."""
    args = argparse.Namespace(path="fake.py", mode="symbolic", verbose=False)
    with patch("pathlib.Path.exists", return_value=False):
        assert cmd_scan(args) == 1


def test_cmd_scan_expands_literal_glob_for_symbolic_directory_scan(tmp_path: Path) -> None:
    """PowerShell-style literal globs should scan matching files instead of failing."""
    target_dir = tmp_path / "targets"
    target_dir.mkdir()
    (target_dir / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (target_dir / "notes.txt").write_text("skip\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(target_dir / "*.py"),
        mode="symbolic",
        format="json",
        output=None,
        verbose=False,
        visualize=False,
        stats=False,
        reproduce=False,
        max_paths=200,
        max_depth=321,
        timeout=30,
        workers=1,
        auto=False,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
    )
    observed: dict[str, object] = {}

    def _fake_symbolic_scan(call_args: argparse.Namespace, path: Path, start_time: float) -> int:
        _ = start_time
        observed["path"] = path
        observed["pattern"] = getattr(call_args, "_scan_glob_pattern", None)
        return 0

    with patch(
        "pysymex._internal.cli.commands.scan.command.handle_symbolic_scan",
        side_effect=_fake_symbolic_scan,
    ):
        rc = cmd_scan(args)

    assert rc == 0
    assert observed["path"] == target_dir
    assert observed["pattern"] == "*.py"


def test_cmd_scan_profile_enables_stats_without_trace(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("def f():\n    return 1\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(target),
        verbose=False,
        profile=True,
        stats=False,
        trace=False,
    )
    observed: dict[str, bool] = {}

    def fake_scan(call_args: argparse.Namespace, _path: Path, _start: float) -> int:
        observed["stats"] = call_args.stats
        observed["trace"] = call_args.trace
        return 0

    with (
        patch(
            "pysymex._internal.cli.commands.scan.command.handle_symbolic_scan",
            side_effect=fake_scan,
        ),
        patch("pysymex._internal.stats.runtime.enable_console_sink"),
        patch("pysymex._internal.stats.runtime.start"),
        patch("pysymex._internal.stats.runtime.stop"),
    ):
        assert cmd_scan(args) == 0

    assert observed == {"stats": True, "trace": False}


def test_cmd_scan_profile_baseline_enables_profile_stats_without_trace(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text("def f():\n    return 1\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(target),
        verbose=False,
        profile=False,
        profile_baseline=str(tmp_path / "before.json"),
        stats=False,
        trace=False,
    )
    observed: dict[str, bool] = {}

    def fake_scan(call_args: argparse.Namespace, _path: Path, _start: float) -> int:
        observed["profile"] = call_args.profile
        observed["stats"] = call_args.stats
        observed["trace"] = call_args.trace
        return 0

    with (
        patch(
            "pysymex._internal.cli.commands.scan.command.handle_symbolic_scan",
            side_effect=fake_scan,
        ),
        patch("pysymex._internal.stats.runtime.enable_console_sink"),
        patch("pysymex._internal.stats.runtime.start"),
        patch("pysymex._internal.stats.runtime.stop"),
    ):
        assert cmd_scan(args) == 0

    assert observed == {"profile": True, "stats": True, "trace": False}


def test_format_scan_profile_reports_evidence_counters() -> None:
    result = ScanResult(
        file_path="target.py",
        timestamp="now",
        issues=[
            {"kind": "TYPE_ERROR"},
            {"kind": "INDEX_ERROR", "replay_status": "confirmed"},
        ],
        paths_explored=7,
        paths_pruned=3,
        degraded_passes=["unsupported_opcode", "resource_limit_time"],
        solver_stats={
            "z3_check_calls": 5,
            "unknown_results": 1,
            "solver_time_ms": 12.5,
            "detector_sink_attempts": 4,
        },
    )

    profile = format_scan_profile([result], ".pysymex/traces")

    assert "paths explored: 7" in profile
    assert "paths pruned: 3" in profile
    assert "detector sink attempts: 4" in profile
    assert "candidate issues: 1" in profile
    assert "confirmed issues: 1" in profile


def test_handle_symbolic_scan_profile_writes_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target.py"
    target.write_text("def f():\n    return 1\n", encoding="utf-8")
    profile_dir = tmp_path / "profiles"
    args = argparse.Namespace(
        path=str(target),
        mode="symbolic",
        format="json",
        output=None,
        verbose=False,
        visualize=False,
        stats=False,
        profile=True,
        profile_mode="sample",
        profile_sample_interval_ms=5.0,
        profile_output_dir=str(profile_dir),
        reproduce=False,
        max_paths=200,
        max_depth=321,
        timeout=30,
        workers=0,
        auto=False,
        no_sandbox=False,
        detect_overflow=False,
        trace=True,
        trace_output_dir=str(tmp_path / "traces"),
        trace_verbosity="delta_only",
    )
    scan_result = ScanResult(
        file_path=str(target),
        timestamp="2026-06-14T00:00:00",
        paths_explored=3,
        elapsed_time=0.25,
        solver_stats={"z3_check_calls": 2, "solver_time_ms": 12.5},
    )

    with (
        patch(
            "pysymex._internal.cli.commands.scan.symbolic.call_with_supported_kwargs",
            return_value=scan_result,
        ),
        patch("pysymex._internal.cli.commands.scan.symbolic.emit_cli_output"),
    ):
        rc = handle_symbolic_scan(args, target, time.time())

    assert rc == 0
    assert list(profile_dir.glob("*.samples.json"))
    summary_path = next(profile_dir.glob("*.summary.json"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["configuration"]["max_depth"] == 321
    assert summary["configuration"]["target_path"] == str(target)
    output = capsys.readouterr().out
    assert "Developer Profile" in output
    assert "Bottleneck Signals" in output
    assert "profile summary:" in output


def test_format_symbolic_text_report() -> None:
    """Test format_symbolic_text_report behavior."""
    from pysymex._internal.cli.formatters.text.formatter import CliTextFormatter

    fmt = CliTextFormatter(use_rich=False)
    text = fmt.format_symbolic([], 0, 0.0, False)
    assert "pysymex - formal verification report" in text


def test_get_symbolic_sarif() -> None:
    """Test get_symbolic_sarif behavior."""
    from pysymex._internal.cli.formatters.sarif import SarifFormatter

    with patch("pysymex._internal.reporting.sarif.generator.SARIFGenerator") as mock_gen:
        mock_sarif = MagicMock()
        mock_sarif.to_json.return_value = "{}"
        mock_gen.return_value.generate.return_value = mock_sarif
        fmt = SarifFormatter()
        assert fmt.format_symbolic([], 0, 0.0) == "{}"


def test_handle_symbolic_scan_forwards_single_file_execution_policy(tmp_path: Path) -> None:
    """Single-file symbolic scans forward the active execution policy."""
    file_path = tmp_path / "sample.py"
    file_path.write_text("def f(x):\n    return x\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(file_path),
        mode="symbolic",
        format="json",
        output=None,
        verbose=False,
        visualize=False,
        stats=False,
        reproduce=False,
        max_paths=200,
        max_depth=321,
        timeout=30,
        workers=0,
        auto=False,
        no_sandbox=False,
        detect_overflow=True,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
    )
    observed: dict[str, object] = {}

    def _fake_call(
        func: object,
        *call_args: object,
        **call_kwargs: object,
    ) -> object:
        _ = func
        _ = call_args
        observed.update(call_kwargs)
        return ScanResult(
            file_path=str(file_path),
            timestamp="2026-04-30T00:00:00",
            issues=[],
        )

    with patch(
        "pysymex._internal.cli.commands.scan.symbolic.call_with_supported_kwargs",
        side_effect=_fake_call,
    ):
        with patch("pysymex._internal.cli.commands.scan.symbolic.emit_cli_output"):
            rc = handle_symbolic_scan(args, file_path, 0.0)

    assert rc == 0
    assert observed["use_sandbox"] is True
    assert observed["max_depth"] == 321
    assert observed["detect_overflow"] is True


def test_handle_symbolic_scan_forwards_directory_execution_policy(tmp_path: Path) -> None:
    """Directory symbolic scans forward the active execution policy."""
    dir_path = tmp_path / "src"
    dir_path.mkdir()
    args = argparse.Namespace(
        path=str(dir_path),
        mode="symbolic",
        format="json",
        output=None,
        verbose=False,
        visualize=False,
        stats=False,
        reproduce=False,
        max_paths=200,
        max_depth=321,
        timeout=30,
        workers=0,
        auto=False,
        no_sandbox=True,
        detect_overflow=True,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
    )
    observed: dict[str, object] = {}

    def _fake_call(
        func: object,
        *call_args: object,
        **call_kwargs: object,
    ) -> object:
        _ = func
        _ = call_args
        observed.update(call_kwargs)
        return []

    with patch(
        "pysymex._internal.cli.commands.scan.symbolic.call_with_supported_kwargs",
        side_effect=_fake_call,
    ):
        with patch("pysymex._internal.cli.commands.scan.symbolic.emit_cli_output"):
            rc = handle_symbolic_scan(args, dir_path, 0.0)

    assert rc == 0
    assert observed["use_sandbox"] is False
    assert observed["max_depth"] == 321
    assert observed["detect_overflow"] is True
    assert observed["pattern"] == "**/*.py"


def test_publish_scan_stats_uses_scan_result_aggregates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Directory scans should make parent-visible result metrics available to --stats."""

    class DummyRegistry:
        def __init__(self) -> None:
            self.global_metrics: dict[str, float | int | str] = {"total_paths_explored": 1.0}
            self.flushes = 0

        def flush(self) -> None:
            self.flushes += 1

    dummy_registry = DummyRegistry()
    emitted: list[tuple[EventType, float]] = []

    def fake_emit(event_type: EventType, value: float = 0.0, metadata: object = None) -> None:
        _ = metadata
        emitted.append((event_type, value))

    monkeypatch.setattr(stats_runtime, "registry", dummy_registry)
    monkeypatch.setattr(stats_runtime, "emit", fake_emit)
    args = argparse.Namespace(stats=True)
    results = [
        ScanResult(
            file_path="a.py",
            timestamp="2026-04-30T00:00:00",
            issues=[],
            paths_explored=4,
            avg_memory_mb=80.0,
            solver_stats={
                "queries": 4,
                "sat_results": 2,
                "unsat_results": 1,
                "unknown_results": 1,
            },
        ),
        ScanResult(
            file_path="b.py",
            timestamp="2026-04-30T00:00:00",
            issues=[],
            paths_explored=2,
            avg_memory_mb=100.0,
            solver_stats={
                "queries": 3,
                "sat_results": 1,
                "unsat_results": 1,
                "unknown_results": 1,
            },
        ),
    ]

    publish_scan_stats_if_requested(args, results)

    assert dummy_registry.flushes == 2
    assert (EventType.PATH_EXPLORED, 5.0) in emitted
    assert (EventType.SCAN_AVG_MEMORY, 90.0) in emitted
    assert (EventType.SOLVER_QUERY, 7.0) in emitted
    assert (EventType.SOLVER_SAT, 3.0) in emitted
    assert (EventType.SOLVER_UNSAT, 2.0) in emitted
    assert (EventType.SOLVER_UNKNOWN, 2.0) in emitted


def test_publish_scan_stats_does_not_double_count_live_solver_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-process scans should not republish solver counters already collected live."""

    class DummyRegistry:
        def __init__(self) -> None:
            self.global_metrics: dict[str, float | int | str] = {
                "total_paths_explored": 4.0,
                "solver_queries": 4,
                "solver_sat": 2,
                "solver_unsat": 1,
                "solver_unknown": 1,
            }
            self.flushes = 0

        def flush(self) -> None:
            self.flushes += 1

    dummy_registry = DummyRegistry()
    emitted: list[tuple[EventType, float]] = []

    def fake_emit(event_type: EventType, value: float = 0.0, metadata: object = None) -> None:
        _ = metadata
        emitted.append((event_type, value))

    monkeypatch.setattr(stats_runtime, "registry", dummy_registry)
    monkeypatch.setattr(stats_runtime, "emit", fake_emit)
    args = argparse.Namespace(stats=True)
    results = [
        ScanResult(
            file_path="a.py",
            timestamp="2026-04-30T00:00:00",
            issues=[],
            paths_explored=4,
            solver_stats={
                "queries": 4,
                "sat_results": 2,
                "unsat_results": 1,
                "unknown_results": 1,
            },
        )
    ]

    publish_scan_stats_if_requested(args, results)

    assert dummy_registry.flushes == 2
    assert emitted == []
