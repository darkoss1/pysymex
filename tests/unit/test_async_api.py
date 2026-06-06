"""Tests for the unsuffixed async public API helpers."""

from __future__ import annotations

import sys
from inspect import iscoroutinefunction

import pytest

import pysymex.api as api
import pysymex.api.runtime as runtime_api
from pysymex.execution.results.result import ExecutionResult
from tests.unit.sandbox.live_sandbox_helpers import live_sandbox_skip_reason


def test_public_api_exports_only_unsuffixed_async_operations() -> None:
    """The API exposes one public name per async operation, without *_async aliases."""
    assert api.analyze is runtime_api.analyze
    assert api.analyze_code is runtime_api.analyze_code
    assert api.analyze_file is runtime_api.analyze_file
    assert api.scan_directory is runtime_api.scan_directory

    assert iscoroutinefunction(api.analyze)
    assert iscoroutinefunction(api.analyze_code)
    assert iscoroutinefunction(api.analyze_file)
    assert iscoroutinefunction(api.scan_directory)


class TestTimeoutFromKwargs:
    """Tests for timeout_from_kwargs helper."""

    def test_default_timeout(self) -> None:
        """Empty kwargs yields default 60.0 seconds."""
        result = runtime_api.timeout_from_kwargs({})
        assert result == 60.0

    def test_custom_timeout(self) -> None:
        """Custom timeout value is extracted."""
        result = runtime_api.timeout_from_kwargs({"timeout": 30.0})
        assert result == 30.0

    def test_int_timeout_converted(self) -> None:
        """Integer timeout is converted to float."""
        result = runtime_api.timeout_from_kwargs({"timeout": 10})
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
async def test_analyze_runs_as_unsuffixed_async_api() -> None:
    """analyze runs symbolic execution asynchronously."""

    def safe(x: int) -> int:
        return x + 1

    result = await api.analyze(safe, {"x": "int"}, max_paths=10, timeout=5.0)
    assert hasattr(result, "issues")


@pytest.mark.asyncio
@pytest.mark.timeout(30)
@_resume_unsupported
async def test_analyze_code_runs_as_unsuffixed_async_api() -> None:
    """analyze_code compiles and executes code asynchronously."""
    result = await api.analyze_code("x = 1 + 2", timeout=5.0)
    assert hasattr(result, "issues")


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_analyze_code_forwards_timeout_to_sync_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """analyze_code maps timeout to the sync implementation's timeout_seconds setting."""
    captured_kwargs: dict[str, object] = {}

    def fake_analyze_code_sync(
        code: str,
        symbolic_vars: object = None,
        **kwargs: object,
    ) -> ExecutionResult:
        assert code == "x = 1 + 2"
        assert symbolic_vars is None
        captured_kwargs.update(kwargs)
        return ExecutionResult(function_name="<string>")

    monkeypatch.setattr(runtime_api, "_analyze_code_sync", fake_analyze_code_sync)

    result = await api.analyze_code("x = 1 + 2", timeout=5.0)

    assert hasattr(result, "issues")
    assert captured_kwargs["timeout_seconds"] == 5.0
    assert "timeout" not in captured_kwargs


@pytest.mark.asyncio
@pytest.mark.timeout(30)
@_resume_unsupported
async def test_analyze_file_runs_as_unsuffixed_async_api(tmp_path: object) -> None:
    """analyze_file analyses a function from a file asynchronously."""
    from pathlib import Path

    reason = live_sandbox_skip_reason()
    if reason is not None:
        pytest.skip(reason)

    p = Path(str(tmp_path)) / "sample.py"
    p.write_text("def add(x, y):\n    return x + y\n", encoding="utf-8")
    result = await api.analyze_file(p, "add", {"x": "int", "y": "int"}, timeout=5.0)
    assert hasattr(result, "issues")


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_scan_directory_runs_as_unsuffixed_async_api(tmp_path: object) -> None:
    """scan_directory on empty dir returns empty list."""
    from pathlib import Path

    empty = Path(str(tmp_path)) / "empty"
    empty.mkdir()
    results = await api.scan_directory(empty, verbose=False, timeout=5.0)
    assert results == []
