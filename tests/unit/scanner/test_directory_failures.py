"""Tests for explicit directory scanner failure results."""

from __future__ import annotations

import concurrent.futures
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import patch

from pysymex._internal.scanner.directory.parallel import scan_parallel_strategy
from pysymex._internal.scanner.directory.sequential import scan_sequential_strategy
from pysymex._internal.scanner.types import ScanResult


def test_sequential_scan_preserves_unexpected_file_failure(tmp_path: Path) -> None:
    """A failed sequential file scan remains visible in directory results."""
    target = tmp_path / "broken.py"
    target.write_text("x = 1\n", encoding="utf-8")

    with patch(
        "pysymex._internal.scanner.directory.sequential.scan_file",
        side_effect=RuntimeError("worker stopped"),
    ):
        results = scan_sequential_strategy(
            [target],
            verbose=False,
            max_paths=10,
            timeout=5.0,
            auto_tune=False,
            use_sandbox=False,
        )

    assert len(results) == 1
    assert results[0].file_path == str(target)
    assert results[0].error == "Scan Error: RuntimeError(worker stopped)"


def test_sequential_scan_reuses_execution_setup_when_trace_disabled(tmp_path: Path) -> None:
    """Tiny sequential directory scans should not rebuild executor setup per file."""
    targets: list[Path] = []
    for index in range(3):
        target = tmp_path / f"case_{index}.py"
        target.write_text("x = 1\n", encoding="utf-8")
        targets.append(target)

    shared_setup = object()
    seen_setups: list[object] = []

    def fake_scan_file(file_path: Path, *args: object, **kwargs: object) -> ScanResult:
        _ = args
        seen_setups.append(kwargs["execution_setup"])
        return ScanResult(file_path=str(file_path), timestamp="now")

    with (
        patch(
            "pysymex._internal.execution.scan.setup.build_scan_execution_setup",
            return_value=shared_setup,
        ) as build_setup,
        patch(
            "pysymex._internal.scanner.directory.sequential.scan_file",
            side_effect=fake_scan_file,
        ),
    ):
        results = scan_sequential_strategy(
            targets,
            verbose=False,
            max_paths=10,
            timeout=5.0,
            auto_tune=False,
            use_sandbox=False,
            trace_enabled=False,
        )

    assert len(results) == 3
    build_setup.assert_called_once()
    assert seen_setups == [shared_setup, shared_setup, shared_setup]


def test_parallel_scan_preserves_unexpected_file_failure(tmp_path: Path) -> None:
    """A failed process worker remains visible in directory results."""
    target = tmp_path / "broken.py"
    target.write_text("x = 1\n", encoding="utf-8")

    class FailedExecutor:
        def __enter__(self) -> FailedExecutor:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: object,
        ) -> None:
            _ = exc_type
            _ = exc_value
            _ = traceback

        def submit(self, *args: object, **kwargs: object) -> concurrent.futures.Future[ScanResult]:
            _ = args
            _ = kwargs
            future: concurrent.futures.Future[ScanResult] = concurrent.futures.Future()
            future.set_exception(RuntimeError("worker stopped"))
            return future

    with patch(
        "pysymex._internal.scanner.directory.parallel.concurrent.futures.ProcessPoolExecutor",
        return_value=FailedExecutor(),
    ):
        results = scan_parallel_strategy(
            [target],
            workers_count=1,
            verbose=False,
            max_paths=10,
            timeout=5.0,
            auto_tune=False,
            use_sandbox=False,
        )

    assert len(results) == 1
    assert results[0].file_path == str(target)
    assert results[0].error == "Scan Error: RuntimeError(worker stopped)"


def test_parallel_scan_returns_results_in_stable_path_order(tmp_path: Path) -> None:
    """Process completion order must not determine returned directory order."""
    targets = [tmp_path / "a.py", tmp_path / "b.py"]
    for target in targets:
        target.write_text("x = 1\n", encoding="utf-8")

    class CompletedExecutor:
        def __enter__(self) -> CompletedExecutor:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: object,
        ) -> None:
            _ = exc_type
            _ = exc_value
            _ = traceback

        def submit(self, *args: object, **kwargs: object) -> concurrent.futures.Future[ScanResult]:
            _ = args
            file_path = kwargs["file_path"]
            assert isinstance(file_path, Path)
            future: concurrent.futures.Future[ScanResult] = concurrent.futures.Future()
            future.set_result(ScanResult(file_path=str(file_path), timestamp="now"))
            return future

    def complete_last_first(
        futures: Iterable[concurrent.futures.Future[ScanResult]],
        *,
        return_when: object,
    ) -> tuple[list[concurrent.futures.Future[ScanResult]], set[object]]:
        _ = return_when
        return list(reversed(list(futures))), set()

    with (
        patch(
            "pysymex._internal.scanner.directory.parallel.concurrent.futures.ProcessPoolExecutor",
            return_value=CompletedExecutor(),
        ),
        patch(
            "pysymex._internal.scanner.directory.parallel.concurrent.futures.wait",
            side_effect=complete_last_first,
        ),
    ):
        results = scan_parallel_strategy(
            targets,
            workers_count=2,
            verbose=False,
            max_paths=10,
            timeout=5.0,
            auto_tune=False,
            use_sandbox=False,
        )

    assert [Path(result.file_path).name for result in results] == ["a.py", "b.py"]


def test_parallel_sandbox_scan_initializes_worker_context(tmp_path: Path) -> None:
    """Sandboxed process workers should get a reusable bytecode extraction context."""
    targets = [tmp_path / "a.py", tmp_path / "b.py"]
    for target in targets:
        target.write_text("x = 1\n", encoding="utf-8")

    executor_kwargs: dict[str, object] = {}

    class CompletedExecutor:
        def __init__(self, *args: object, **kwargs: object) -> None:
            _ = args
            executor_kwargs.update(kwargs)

        def __enter__(self) -> CompletedExecutor:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: object,
        ) -> None:
            _ = exc_type
            _ = exc_value
            _ = traceback

        def submit(self, *args: object, **kwargs: object) -> concurrent.futures.Future[ScanResult]:
            _ = args
            file_path = kwargs["file_path"]
            assert isinstance(file_path, Path)
            future: concurrent.futures.Future[ScanResult] = concurrent.futures.Future()
            future.set_result(ScanResult(file_path=str(file_path), timestamp="now"))
            return future

    def complete_all(
        futures: Iterable[concurrent.futures.Future[ScanResult]],
        *,
        return_when: object,
    ) -> tuple[list[concurrent.futures.Future[ScanResult]], set[object]]:
        _ = return_when
        return list(futures), set()

    with (
        patch(
            "pysymex._internal.scanner.directory.parallel.concurrent.futures.ProcessPoolExecutor",
            side_effect=CompletedExecutor,
        ),
        patch(
            "pysymex._internal.scanner.directory.parallel.concurrent.futures.wait",
            side_effect=complete_all,
        ),
    ):
        results = scan_parallel_strategy(
            targets,
            workers_count=2,
            verbose=False,
            max_paths=10,
            timeout=5.0,
            auto_tune=False,
            use_sandbox=True,
        )

    initializer = executor_kwargs.get("initializer")
    assert callable(initializer)
    assert getattr(initializer, "__name__") == "_initialize_scan_worker"
    assert executor_kwargs["initargs"] == (True,)
    assert [Path(result.file_path).name for result in results] == ["a.py", "b.py"]
