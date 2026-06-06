from __future__ import annotations

import builtins
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from pysymex.execution.config.settings import ExecutionConfig
from pysymex.scanner.trace_runtime import install_scanner_tracer

if TYPE_CHECKING:
    from pysymex.execution.executors import SymbolicExecutor


def test_default_disabled_trace_path_skips_heavy_tracing_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default disabled tracing should not import the telemetry stack."""
    monkeypatch.delenv("PY_SYMEX_TRACE", raising=False)
    real_import = builtins.__import__

    def guarded_import(
        name: str,
        globals_: Mapping[str, object] | None = None,
        locals_: Mapping[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name.startswith("pysymex.tracing"):
            raise AssertionError(f"unexpected tracing import: {name}")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    tracer = install_scanner_tracer(
        trace_enabled=None,
        trace_output_dir=None,
        trace_verbosity="delta_only",
        file_path=Path("target.py"),
        config=ExecutionConfig(),
        executor=cast("SymbolicExecutor", object()),
    )

    assert tracer is None
