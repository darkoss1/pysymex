from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import pysymex.scanner.async_scanner as async_scanner
from pysymex.scanner.types import ScanResult


def test_scan_directory_returns_empty_for_no_files(tmp_path: Path) -> None:
    results = asyncio.run(async_scanner.scan_directory(tmp_path, verbose=False))
    assert results == []


def test_scan_directory_scans_single_python_file(tmp_path: Path) -> None:
    file_path = tmp_path / "x.py"
    file_path.write_text("x = 1\n", encoding="utf-8")

    results = asyncio.run(
        async_scanner.scan_directory(
            tmp_path,
            verbose=False,
            max_concurrency=1,
            timeout=5.0,
            max_paths=10,
            use_sandbox=False,
        )
    )
    assert len(results) == 1
    assert results[0].file_path.endswith("x.py")


def test_scan_directory_returns_results_in_stable_path_order(tmp_path: Path) -> None:
    """Async scanner should return results sorted by file path for deterministic output."""
    (tmp_path / "b.py").write_text("x = 2\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")

    results = asyncio.run(
        async_scanner.scan_directory(
            tmp_path,
            verbose=False,
            max_concurrency=8,
            timeout=5.0,
            max_paths=10,
            use_sandbox=False,
        )
    )
    file_names = [Path(result.file_path).name for result in results]
    assert file_names == sorted(file_names)


def test_scan_directory_raises_worker_failures_as_exception_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async scans must not silently report partial success after a worker failure."""
    (tmp_path / "broken.py").write_text("x = 1\n", encoding="utf-8")

    async def fail_scan(*args: object, **kwargs: object) -> async_scanner.ScanResult:
        _ = args
        _ = kwargs
        raise RuntimeError("worker stopped")

    monkeypatch.setattr(async_scanner, "_scan_file_async", fail_scan)

    with pytest.raises(ExceptionGroup, match="async scan: 1 file") as caught:
        asyncio.run(async_scanner.scan_directory(tmp_path, verbose=False, max_concurrency=1))

    assert isinstance(caught.value.exceptions[0], RuntimeError)


def test_scan_directory_forwards_execution_policy_to_file_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async directory scans must preserve execution-policy arguments."""
    target = tmp_path / "target.py"
    target.write_text("x = 1\n", encoding="utf-8")
    observed: dict[str, object] = {}

    async def capture_scan(**kwargs: object) -> ScanResult:
        observed.update(kwargs)
        return ScanResult(file_path=str(target), timestamp="now")

    monkeypatch.setattr(async_scanner, "_scan_file_async", capture_scan)

    asyncio.run(
        async_scanner.scan_directory(
            tmp_path,
            verbose=False,
            max_concurrency=1,
            use_sandbox=False,
            deterministic_mode=True,
            random_seed=9,
            no_cache=True,
            max_iterations=17,
            enable_fp_filtering=False,
        )
    )

    assert observed["use_sandbox"] is False
    assert observed["deterministic_mode"] is True
    assert observed["random_seed"] == 9
    assert observed["no_cache"] is True
    assert observed["max_iterations"] == 17
    assert observed["enable_fp_filtering"] is False


def test_scan_directory_normalizes_input_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async library scans use the same normalized target boundary as sync scans."""
    target = tmp_path / "target.py"
    target.write_text("x = 1\n", encoding="utf-8")
    normalized_inputs: list[str | Path] = []

    def normalize(path: str | Path) -> Path:
        normalized_inputs.append(path)
        return tmp_path

    async def capture_scan(**kwargs: object) -> ScanResult:
        file_path = kwargs["file_path"]
        assert isinstance(file_path, Path)
        return ScanResult(file_path=str(file_path), timestamp="now")

    monkeypatch.setattr(async_scanner, "normalize_input_path", normalize)
    monkeypatch.setattr(async_scanner, "_scan_file_async", capture_scan)

    results = asyncio.run(
        async_scanner.scan_directory("unexpanded-target", verbose=False, max_concurrency=1)
    )

    assert normalized_inputs == ["unexpanded-target"]
    assert [Path(result.file_path).name for result in results] == ["target.py"]
