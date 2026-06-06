import argparse
from unittest.mock import patch, MagicMock
from pathlib import Path

import pytest

import pysymex.cli.scan
import pysymex.stats
from pysymex.cli.scan.shared import publish_scan_stats_if_requested
from pysymex.stats import EventType
from pysymex.scanner.types import ScanResult


def test_cmd_scan() -> None:
    """Test cmd_scan behavior."""
    args = argparse.Namespace(path="fake.py", mode="symbolic", verbose=False, recursive=False)
    with patch("pathlib.Path.exists", return_value=False):
        assert pysymex.cli.scan.cmd_scan(args) == 1


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
        recursive=False,
        visualize=False,
        stats=False,
        reproduce=False,
        max_paths=200,
        timeout=30,
        workers=1,
        auto=False,
        deterministic=False,
        seed=42,
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

    with patch("pysymex.cli.scan.handle_symbolic_scan", side_effect=_fake_symbolic_scan):
        rc = pysymex.cli.scan.cmd_scan(args)

    assert rc == 0
    assert observed["path"] == target_dir
    assert observed["pattern"] == "*.py"


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_cmd_scan_async() -> None:
    """Test cmd_scan_async behavior."""
    args = argparse.Namespace(path="fake.py", mode="symbolic", verbose=False, recursive=False)
    with patch("pathlib.Path.exists", return_value=False):
        assert await pysymex.cli.scan.cmd_scan_async(args) == 1


@pytest.mark.asyncio
async def test_cmd_scan_async_closes_shutdown_handle(tmp_path: Path) -> None:
    """Async scan command should restore installed shutdown handlers."""
    target = tmp_path / "sample.py"
    target.write_text("def f():\n    return 1\n", encoding="utf-8")
    args = argparse.Namespace(path=str(target), mode="symbolic", verbose=False)

    class FakeShutdownHandle:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    handle = FakeShutdownHandle()

    with patch("pysymex.core.shutdown.install_signal_handlers", return_value=handle):
        with patch("pysymex.cli.scan.async_runner._handle_symbolic_scan_async", return_value=0):
            assert await pysymex.cli.scan.cmd_scan_async(args) == 0

    assert handle.closed is True


def test_format_symbolic_text_report() -> None:
    """Test format_symbolic_text_report behavior."""
    from pysymex.cli.formatters.text import TextFormatter

    fmt = TextFormatter(use_rich=False)
    text = fmt.format_symbolic([], 0, 0.0, False)
    assert "pysymex - formal verification report" in text


def test_get_symbolic_sarif() -> None:
    """Test get_symbolic_sarif behavior."""
    from pysymex.cli.formatters.sarif import SarifFormatter

    with patch("pysymex.reporting.sarif.SARIFGenerator") as mock_gen:
        mock_sarif = MagicMock()
        mock_sarif.to_json.return_value = "{}"
        mock_gen.return_value.generate.return_value = mock_sarif
        fmt = SarifFormatter()
        assert fmt.format_symbolic([], 0, 0.0) == "{}"


def test_handle_symbolic_scan_forces_deterministic_mode_for_single_file(tmp_path: Path) -> None:
    """Single-file symbolic scans force deterministic mode for stable path coverage."""
    file_path = tmp_path / "sample.py"
    file_path.write_text("def f(x):\n    return x\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(file_path),
        mode="symbolic",
        format="json",
        output=None,
        verbose=False,
        recursive=False,
        visualize=False,
        stats=False,
        reproduce=False,
        max_paths=200,
        timeout=30,
        workers=0,
        auto=False,
        no_sandbox=False,
        deterministic=False,
        seed=42,
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

    with patch("pysymex.cli.scan.symbolic.call_with_supported_kwargs", side_effect=_fake_call):
        with patch("pysymex.cli.scan.symbolic.emit_cli_output"):
            rc = pysymex.cli.scan.handle_symbolic_scan(args, file_path, 0.0)

    assert rc == 0
    assert observed["deterministic_mode"] is True
    assert observed["use_sandbox"] is True


def test_handle_symbolic_scan_keeps_directory_deterministic_flag(tmp_path: Path) -> None:
    """Directory symbolic scans preserve explicit deterministic flag value."""
    dir_path = tmp_path / "src"
    dir_path.mkdir()
    args = argparse.Namespace(
        path=str(dir_path),
        mode="symbolic",
        format="json",
        output=None,
        verbose=False,
        recursive=False,
        visualize=False,
        stats=False,
        reproduce=False,
        max_paths=200,
        timeout=30,
        workers=0,
        auto=False,
        no_sandbox=True,
        deterministic=False,
        seed=42,
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

    with patch("pysymex.cli.scan.symbolic.call_with_supported_kwargs", side_effect=_fake_call):
        with patch("pysymex.cli.scan.symbolic.emit_cli_output"):
            rc = pysymex.cli.scan.handle_symbolic_scan(args, dir_path, 0.0)

    assert rc == 0
    assert observed["deterministic_mode"] is False
    assert observed["use_sandbox"] is False


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

    monkeypatch.setattr(pysymex.stats, "registry", dummy_registry)
    monkeypatch.setattr(pysymex.stats, "emit", fake_emit)
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

    monkeypatch.setattr(pysymex.stats, "registry", dummy_registry)
    monkeypatch.setattr(pysymex.stats, "emit", fake_emit)
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
