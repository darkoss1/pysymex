"""Tests for explicit directory scanner failure results."""

from __future__ import annotations

import concurrent.futures
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import patch

from pysymex.scanner.directory.parallel import scan_parallel
from pysymex.scanner.directory.sequential import scan_sequential
from pysymex.scanner.types import ScanResult


def test_sequential_scan_preserves_unexpected_file_failure(tmp_path: Path) -> None:
    """A failed sequential file scan remains visible in directory results."""
    target = tmp_path / "broken.py"
    target.write_text("x = 1\n", encoding="utf-8")

    with patch(
        "pysymex.scanner.directory.sequential.scan_file",
        side_effect=RuntimeError("worker stopped"),
    ):
        results = scan_sequential(
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


def test_parallel_scan_preserves_unexpected_file_failure(tmp_path: Path) -> None:
    """A failed process worker remains visible in directory results."""
    target = tmp_path / "broken.py"
    target.write_text("x = 1\n", encoding="utf-8")

    class FailedExecutor:
        def __enter__(self) -> "FailedExecutor":
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
        "pysymex.scanner.directory.parallel.concurrent.futures.ProcessPoolExecutor",
        return_value=FailedExecutor(),
    ):
        results = scan_parallel(
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
        def __enter__(self) -> "CompletedExecutor":
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
            "pysymex.scanner.directory.parallel.concurrent.futures.ProcessPoolExecutor",
            return_value=CompletedExecutor(),
        ),
        patch(
            "pysymex.scanner.directory.parallel.concurrent.futures.wait",
            side_effect=complete_last_first,
        ),
    ):
        results = scan_parallel(
            targets,
            workers_count=2,
            verbose=False,
            max_paths=10,
            timeout=5.0,
            auto_tune=False,
            use_sandbox=False,
        )

    assert [Path(result.file_path).name for result in results] == ["a.py", "b.py"]
