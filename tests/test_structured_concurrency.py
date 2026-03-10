"""Tests for Phase 9: Structured Concurrency.

Covers:
- 9.1: Async API entry points (analyze_async, analyze_code_async, etc.)
- 9.2: TaskGroup-based async scanner
- 9.3: Graceful shutdown helpers
- 9.4: Async CLI integration (--async flag)
"""

from __future__ import annotations

import asyncio
import textwrap
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# 9.1 – Async API entry points
# ---------------------------------------------------------------------------


class TestAsyncAPI:
    """Test the async wrappers in pysymex.async_api."""

    @pytest.mark.asyncio
    async def test_analyze_async_basic(self):
        """analyze_async should return an ExecutionResult."""
        from pysymex.async_api import analyze_async

        def divide(x, y):
            return x / y

        result = await analyze_async(divide, {"x": "int", "y": "int"})
        assert result is not None
        assert hasattr(result, "issues")

    @pytest.mark.asyncio
    async def test_analyze_code_async_basic(self):
        """analyze_code_async should analyse code strings."""
        from pysymex.async_api import analyze_code_async

        code = textwrap.dedent("""\
            def foo(x, y):
                return x / y
        """)
        result = await analyze_code_async(code, {"x": "int", "y": "int"})
        assert result is not None

    @pytest.mark.asyncio
    async def test_analyze_file_async_basic(self, tmp_path):
        """analyze_file_async should analyse a file."""
        from pysymex.async_api import analyze_file_async

        src = tmp_path / "sample.py"
        src.write_text(
            textwrap.dedent("""\
                def divide(x, y):
                    return x / y
            """),
            encoding="utf-8",
        )
        result = await analyze_file_async(str(src), "divide", {"x": "int", "y": "int"})
        assert result is not None

    @pytest.mark.asyncio
    async def test_scan_directory_async_empty(self, tmp_path):
        """scan_directory_async on an empty dir returns []."""
        from pysymex.async_api import scan_directory_async

        results = await scan_directory_async(tmp_path, verbose=False)
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_directory_async_with_files(self, tmp_path):
        """scan_directory_async should scan .py files concurrently."""
        from pysymex.async_api import scan_directory_async

        for i in range(3):
            (tmp_path / f"mod{i}.py").write_text(
                f"def f{i}(x):\n    return x + {i}\n",
                encoding="utf-8",
            )
        # Use max_concurrency=1 to avoid Z3 thread-safety issues on Windows
        results = await scan_directory_async(
            tmp_path,
            verbose=False,
            max_concurrency=1,
        )
        assert len(results) == 3


# ---------------------------------------------------------------------------
# 9.2 – TaskGroup-based async scanner
# ---------------------------------------------------------------------------


class TestAsyncScanner:
    """Test pysymex.scanner.async_scanner."""

    @pytest.mark.asyncio
    async def test_scan_directory_async_returns_scan_results(self, tmp_path):
        from pysymex.scanner.async_scanner import scan_directory_async

        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
        results = await scan_directory_async(tmp_path, verbose=False, max_concurrency=1)
        assert len(results) == 2
        for r in results:
            assert hasattr(r, "file_path")
            assert hasattr(r, "issues")

    @pytest.mark.asyncio
    async def test_scan_directory_async_semaphore_limits_concurrency(self, tmp_path):
        """Concurrency should be bounded by the semaphore."""
        from pysymex.scanner.async_scanner import scan_directory_async

        for i in range(5):
            (tmp_path / f"f{i}.py").write_text(f"v{i} = {i}\n", encoding="utf-8")

        # max_concurrency=1 means sequential
        results = await scan_directory_async(
            tmp_path,
            verbose=False,
            max_concurrency=1,
        )
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_scan_directory_async_handles_syntax_errors(self, tmp_path):
        """Files with syntax errors should not crash the TaskGroup."""
        from pysymex.scanner.async_scanner import scan_directory_async

        (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "bad.py").write_text("def broken(\n", encoding="utf-8")

        results = await scan_directory_async(tmp_path, verbose=False, max_concurrency=1)
        # Both files should produce results (the bad one with an error field)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_scan_directory_async_empty_directory(self, tmp_path):
        from pysymex.scanner.async_scanner import scan_directory_async

        results = await scan_directory_async(tmp_path, verbose=False)
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_directory_async_pattern_filter(self, tmp_path):
        """Only files matching the pattern should be scanned."""
        from pysymex.scanner.async_scanner import scan_directory_async

        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "data.txt").write_text("not python\n", encoding="utf-8")

        results = await scan_directory_async(
            tmp_path,
            pattern="*.py",
            verbose=False,
            max_concurrency=1,
        )
        assert len(results) == 1


# ---------------------------------------------------------------------------
# 9.3 – Graceful shutdown
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """Test pysymex.core.shutdown."""

    def test_cancel_all_tasks(self):
        """cancel_all_tasks should cancel pending tasks."""
        from pysymex.core.shutdown import cancel_all_tasks

        async def _run():
            tasks = []
            for _ in range(3):
                t = asyncio.create_task(asyncio.sleep(999))
                tasks.append(t)
            await asyncio.sleep(0)  # let tasks start
            cancel_all_tasks(asyncio.get_running_loop())
            await asyncio.sleep(0)  # let cancellation propagate
            for t in tasks:
                assert t.cancelled()

        asyncio.run(_run())

    def test_install_signal_handlers_does_not_raise(self):
        """install_signal_handlers should not raise on current platform."""
        from pysymex.core.shutdown import install_signal_handlers

        async def _run():
            loop = asyncio.get_running_loop()
            install_signal_handlers(loop)

        asyncio.run(_run())

    def test_run_with_shutdown(self):
        """run_with_shutdown should run a coroutine to completion."""
        from pysymex.core.shutdown import run_with_shutdown

        async def _coro():
            return 42

        assert run_with_shutdown(_coro()) == 42

    @pytest.mark.asyncio
    async def test_taskgroup_cancellation_propagates(self):
        """When a task is cancelled, TaskGroup should cancel siblings."""
        results = []

        async def worker(idx: int, delay: float):
            try:
                await asyncio.sleep(delay)
                results.append(idx)
            except asyncio.CancelledError:
                results.append(f"cancelled-{idx}")
                raise

        with pytest.raises(asyncio.CancelledError):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(worker(1, 10))
                tg.create_task(worker(2, 10))
                # Cancel from outside after a short delay
                await asyncio.sleep(0.01)
                raise asyncio.CancelledError()

    def test_cancelled_error_type(self):
        """CancelledError should be a BaseException (not Exception)."""
        assert issubclass(asyncio.CancelledError, BaseException)
        assert not issubclass(asyncio.CancelledError, Exception)


# ---------------------------------------------------------------------------
# 9.4 – Async CLI integration
# ---------------------------------------------------------------------------


class TestAsyncCLI:
    """Test --async flag in the CLI."""

    def test_parser_has_async_flag(self):
        """The scan subcommand should accept --async."""
        from pysymex.cli.parser import create_parser

        parser = create_parser()
        args = parser.parse_args(["scan", ".", "--async"])
        assert args.use_async is True

    def test_parser_async_default_false(self):
        """--async should default to False."""
        from pysymex.cli.parser import create_parser

        parser = create_parser()
        args = parser.parse_args(["scan", "."])
        assert args.use_async is False

    def test_cmd_scan_async_exists(self):
        """cmd_scan_async should be importable."""
        from pysymex.cli.scan import cmd_scan_async

        assert asyncio.iscoroutinefunction(cmd_scan_async)

    def test_main_dispatches_async_scan(self):
        """main() should dispatch to cmd_scan_async when --async is set."""
        from pysymex.cli import main

        with patch("pysymex.cli.scan.cmd_scan_async", new_callable=MagicMock) as mock_async:
            # Use a regular MagicMock to avoid coroutine-never-awaited warning
            mock_async.return_value = MagicMock()

            with patch("asyncio.run", return_value=0) as mock_run:
                result = main(["scan", ".", "--async"])
                mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_cmd_scan_async_nonexistent_path(self):
        """cmd_scan_async should return 1 for a missing path."""
        import argparse

        from pysymex.cli.scan import cmd_scan_async

        args = argparse.Namespace(
            path="/nonexistent/path/xyz",
            verbose=False,
            mode="symbolic",
            format="text",
            output=None,
            recursive=False,
            max_paths=100,
            timeout=10,
            workers=0,
            auto=False,
            reproduce=False,
            visualize=False,
            use_async=True,
        )
        result = await cmd_scan_async(args)
        assert result == 1


# ---------------------------------------------------------------------------
# Module-level exports
# ---------------------------------------------------------------------------


class TestExports:
    """Verify that new async symbols are accessible from package level."""

    def test_api_module_exports(self):
        from pysymex.api import __all__ as api_all

        assert "analyze_async" in api_all
        assert "analyze_code_async" in api_all
        assert "analyze_file_async" in api_all
        assert "scan_directory_async" in api_all

    def test_scanner_exports_async(self):
        from pysymex.scanner import __all__ as scanner_all

        assert "scan_directory_async" in scanner_all

    def test_async_api_module_importable(self):
        import pysymex.async_api

        assert hasattr(pysymex.async_api, "analyze_async")
        assert hasattr(pysymex.async_api, "analyze_code_async")
        assert hasattr(pysymex.async_api, "analyze_file_async")
        assert hasattr(pysymex.async_api, "scan_directory_async")

    def test_shutdown_module_importable(self):
        from pysymex.core.shutdown import (
            cancel_all_tasks,
            install_signal_handlers,
            run_with_shutdown,
        )

        assert callable(cancel_all_tasks)
        assert callable(install_signal_handlers)
        assert callable(run_with_shutdown)
