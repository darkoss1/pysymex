from __future__ import annotations

import asyncio
from pathlib import Path

import pysymex.scanner.async_scanner as async_scanner


def test_scan_directory_async_returns_empty_for_no_files(tmp_path: Path) -> None:
    results = asyncio.run(async_scanner.scan_directory_async(tmp_path, verbose=False))
    assert results == []


def test_scan_directory_async_scans_single_python_file(tmp_path: Path) -> None:
    file_path = tmp_path / "x.py"
    file_path.write_text("x = 1\n", encoding="utf-8")

    results = asyncio.run(
        async_scanner.scan_directory_async(
            tmp_path,
            verbose=False,
            max_concurrency=1,
            timeout=5.0,
            max_paths=10,
        )
    )
    assert len(results) == 1
    assert results[0].file_path.endswith("x.py")
