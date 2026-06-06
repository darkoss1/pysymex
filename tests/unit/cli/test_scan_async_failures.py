from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

import pytest

from pysymex.cli.scan import cmd_scan_async
from pysymex.scanner.types import ScanResult


@pytest.mark.asyncio
async def test_async_directory_scan_returns_failure_for_worker_exception(tmp_path: Path) -> None:
    """The CLI must not render a successful report for an incomplete async scan."""
    args = argparse.Namespace(
        path=str(tmp_path),
        mode="symbolic",
        verbose=False,
        recursive=False,
        max_paths=10,
        timeout=5.0,
        workers=1,
        auto=False,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
        deterministic=False,
        seed=42,
        no_cache=False,
        max_iterations=0,
        format="json",
        stats=False,
        reproduce=False,
        output=None,
    )
    failure = ExceptionGroup("async scan: 1 file(s) had errors", [RuntimeError("worker stopped")])

    class ShutdownHandle:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    shutdown_handle = ShutdownHandle()
    with (
        patch(
            "pysymex.core.shutdown.install_signal_handlers",
            return_value=shutdown_handle,
        ),
        patch("pysymex.scanner.async_scanner.scan_directory", side_effect=failure),
        patch("pysymex.cli.scan.async_runner.print_cli_error") as print_error,
    ):
        result = await cmd_scan_async(args)

    assert result == 1
    assert shutdown_handle.closed is True
    print_error.assert_called_once_with(f"Async scan failed for 1 file(s): {tmp_path}")


@pytest.mark.asyncio
async def test_async_directory_scan_forwards_cli_execution_policy(tmp_path: Path) -> None:
    """Async CLI options must reach the directory-scanner execution policy."""
    args = argparse.Namespace(
        path=str(tmp_path),
        mode="symbolic",
        verbose=False,
        recursive=False,
        max_paths=10,
        timeout=5.0,
        workers=1,
        auto=False,
        no_sandbox=True,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
        deterministic=True,
        seed=9,
        no_cache=True,
        max_iterations=17,
        format="json",
        stats=False,
        reproduce=False,
        output=None,
    )
    observed: dict[str, object] = {}

    async def capture_directory_scan(*args: object, **kwargs: object) -> list[object]:
        observed["path"] = args[0]
        observed.update(kwargs)
        return []

    class ShutdownHandle:
        def close(self) -> None:
            return None

    with (
        patch("pysymex.core.shutdown.install_signal_handlers", return_value=ShutdownHandle()),
        patch("pysymex.scanner.async_scanner.scan_directory", side_effect=capture_directory_scan),
        patch("pysymex.cli.scan.async_runner.emit_cli_output"),
    ):
        assert await cmd_scan_async(args) == 0

    assert observed["path"] == tmp_path
    assert observed["use_sandbox"] is False
    assert observed["deterministic_mode"] is True
    assert observed["random_seed"] == 9
    assert observed["no_cache"] is True
    assert observed["max_iterations"] == 17


@pytest.mark.asyncio
async def test_async_directory_scan_returns_failure_for_error_result(tmp_path: Path) -> None:
    """Async scan results carrying errors must produce a nonzero CLI result."""
    args = argparse.Namespace(
        path=str(tmp_path),
        mode="symbolic",
        verbose=False,
        recursive=False,
        max_paths=10,
        timeout=5.0,
        workers=1,
        auto=False,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
        deterministic=False,
        seed=42,
        no_cache=False,
        max_iterations=0,
        format="json",
        stats=False,
        reproduce=False,
        output=None,
    )
    failed_result = ScanResult(
        file_path=str(tmp_path / "broken.py"), timestamp="now", error="Error"
    )

    class ShutdownHandle:
        def close(self) -> None:
            return None

    with (
        patch("pysymex.core.shutdown.install_signal_handlers", return_value=ShutdownHandle()),
        patch("pysymex.scanner.async_scanner.scan_directory", return_value=[failed_result]),
        patch("pysymex.cli.scan.async_runner.emit_cli_output"),
    ):
        assert await cmd_scan_async(args) == 1


@pytest.mark.asyncio
async def test_async_directory_scan_returns_failure_for_degraded_result(tmp_path: Path) -> None:
    """Async degraded scans must produce a nonzero CLI result."""
    args = argparse.Namespace(
        path=str(tmp_path),
        mode="symbolic",
        verbose=False,
        recursive=False,
        max_paths=10,
        timeout=5.0,
        workers=1,
        auto=False,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
        deterministic=False,
        seed=42,
        no_cache=False,
        max_iterations=0,
        format="json",
        stats=False,
        reproduce=False,
        output=None,
    )
    degraded_result = ScanResult(
        file_path=str(tmp_path / "degraded.py"),
        timestamp="now",
        degraded_passes=["solver_unknown_detector_query"],
    )

    class ShutdownHandle:
        def close(self) -> None:
            return None

    with (
        patch("pysymex.core.shutdown.install_signal_handlers", return_value=ShutdownHandle()),
        patch("pysymex.scanner.async_scanner.scan_directory", return_value=[degraded_result]),
        patch("pysymex.cli.scan.async_runner.emit_cli_output"),
    ):
        assert await cmd_scan_async(args) == 1


@pytest.mark.asyncio
async def test_async_single_file_scan_forwards_cli_execution_policy(tmp_path: Path) -> None:
    """Single-file async scans must honor the same execution policy as directories."""
    target = tmp_path / "target.py"
    target.write_text("x = 1\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(target),
        mode="symbolic",
        verbose=False,
        recursive=False,
        max_paths=10,
        timeout=5.0,
        workers=1,
        auto=False,
        no_sandbox=True,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
        deterministic=True,
        seed=9,
        no_cache=True,
        max_iterations=17,
        format="json",
        stats=False,
        reproduce=False,
        output=None,
    )
    observed: dict[str, object] = {}

    def capture_scan(*args: object, **kwargs: object) -> ScanResult:
        _ = args
        observed.update(kwargs)
        return ScanResult(file_path=str(target), timestamp="now")

    class ShutdownHandle:
        def close(self) -> None:
            return None

    with (
        patch("pysymex.core.shutdown.install_signal_handlers", return_value=ShutdownHandle()),
        patch("pysymex.scanner.file.scan_file", side_effect=capture_scan),
        patch("pysymex.cli.scan.async_runner.emit_cli_output"),
    ):
        assert await cmd_scan_async(args) == 0

    assert observed["use_sandbox"] is False
    assert observed["deterministic_mode"] is True
    assert observed["random_seed"] == 9
    assert observed["no_cache"] is True
    assert observed["max_iterations"] == 17
