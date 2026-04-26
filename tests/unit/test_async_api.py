"""Tests for pysymex.async_api — async versions of the public API."""

from __future__ import annotations

import sys

import pytest

import pysymex.async_api as mod


class TestTimeoutFromKwargs:
    """Tests for _timeout_from_kwargs helper."""

    def test_default_timeout(self) -> None:
        """Empty kwargs yields default 60.0 seconds."""
        result = mod._timeout_from_kwargs({})
        assert result == 60.0

    def test_custom_timeout(self) -> None:
        """Custom timeout value is extracted."""
        result = mod._timeout_from_kwargs({"timeout": 30.0})
        assert result == 30.0

    def test_int_timeout_converted(self) -> None:
        """Integer timeout is converted to float."""
        result = mod._timeout_from_kwargs({"timeout": 10})
        assert result == 10.0
        assert isinstance(result, float)


_resume_unsupported = pytest.mark.xfail(
    sys.version_info < (3, 13),
    reason="RESUME opcode behavior differs on Python 3.11/3.12",
    strict=False,
)


@pytest.mark.asyncio
@pytest.mark.timeout(30)
@_resume_unsupported
async def test_analyze_async_runs() -> None:
    """analyze_async runs symbolic execution asynchronously."""

    def safe(x: int) -> int:
        return x + 1

    result = await mod.analyze_async(safe, {"x": "int"}, max_paths=10, timeout=5.0)
    assert hasattr(result, "issues")


@pytest.mark.asyncio
@pytest.mark.timeout(30)
@_resume_unsupported
async def test_analyze_code_async_runs() -> None:
    """analyze_code_async compiles and executes code asynchronously."""
    result = await mod.analyze_code_async("x = 1 + 2", timeout=5.0)
    assert hasattr(result, "issues")


@pytest.mark.asyncio
@pytest.mark.timeout(30)
@_resume_unsupported
async def test_analyze_file_async_runs(tmp_path: object) -> None:
    """analyze_file_async analyses a function from a file asynchronously."""
    from pathlib import Path

    p = Path(str(tmp_path)) / "sample.py"
    p.write_text("def add(x, y):\n    return x + y\n", encoding="utf-8")
    result = await mod.analyze_file_async(p, "add", {"x": "int", "y": "int"}, timeout=5.0)
    assert hasattr(result, "issues")


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_scan_directory_async_empty(tmp_path: object) -> None:
    """scan_directory_async on empty dir returns empty list."""
    from pathlib import Path

    empty = Path(str(tmp_path)) / "empty"
    empty.mkdir()
    results = await mod.scan_directory_async(empty, verbose=False, timeout=5.0)
    assert results == []
