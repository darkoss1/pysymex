from __future__ import annotations

import builtins
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.scanner.file import scan_file
from pysymex._internal.scanner.types import ScanResult
from pysymex._internal.tracing.scan import install_scan_tracer

if TYPE_CHECKING:
    from pysymex._internal.execution.executors.core import SymbolicExecutor


_TRUTHINESS_CLOSURE_DIVISION_SOURCE = """
def target(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    class Probe:
        def __init__(self, items: list[int]) -> None:
            self.items = items

        def __bool__(self) -> bool:
            return self.items[-1] == 0

        def push(self, value: int) -> int:
            self.items.append(value)
            return self.items[-1]

    values = [a - b]
    alias = values
    probe = Probe(alias)

    def mutate(value: int) -> int:
        probe.push(value)
        if value > 0:
            alias[0] = alias[0] + value
        else:
            alias[0] = alias[0] - value
        return alias[0]

    total = 0
    if a >= 0:
        total = total + mutate(a)
    else:
        total = total - mutate(a)
    if b >= 0:
        total = total + mutate(b)
    else:
        total = total - mutate(b)
    mutate(c)

    if probe:
        if d == e:
            denom = d - e
        else:
            denom = f or 1
    else:
        denom = f or 1
    return total // denom
"""


def _issue_kinds(result: ScanResult) -> set[str]:
    """Return normalized issue kind strings from a scanner result."""
    kinds: set[str] = set()
    for issue in result.issues:
        kind = issue.get("kind")
        if kind is not None:
            kinds.add(str(kind))
    return kinds


def test_default_disabled_scan_trace_path_skips_heavy_tracing_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default disabled scan tracing should not import the telemetry stack."""
    monkeypatch.delenv("PY_SYMEX_TRACE", raising=False)
    real_import = builtins.__import__

    def guarded_import(
        name: str,
        globals_: Mapping[str, object] | None = None,
        locals_: Mapping[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if (
            name.startswith("pysymex._internal.tracing")
            and name != "pysymex._internal.tracing.scan"
        ):
            raise AssertionError(f"unexpected tracing import: {name}")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    tracer = install_scan_tracer(
        trace_enabled=None,
        trace_output_dir=None,
        trace_verbosity="delta_only",
        file_path=Path("target.py"),
        config=ExecutionConfig(),
        executor=cast("SymbolicExecutor", object()),
    )

    assert tracer is None


def test_scan_trace_preserves_truthiness_closure_division_result(tmp_path: Path) -> None:
    """Tracing must not change feasibility or suppress feasible scanner issues."""
    target = tmp_path / "truthiness_closure_division.py"
    target.write_text(_TRUTHINESS_CLOSURE_DIVISION_SOURCE, encoding="utf-8")

    untraced = scan_file(
        target,
        trace_enabled=False,
        use_sandbox=False,
        no_cache=True,
        max_paths=360,
        max_iterations=10000,
    )
    traced = scan_file(
        target,
        trace_enabled=True,
        trace_output_dir=str(tmp_path / "traces"),
        trace_verbosity="delta_only",
        use_sandbox=False,
        no_cache=True,
        max_paths=360,
        max_iterations=10000,
    )

    assert untraced.error is None
    assert traced.error is None
    assert untraced.degraded_passes == []
    assert traced.degraded_passes == []
    assert "DIVISION_BY_ZERO" in _issue_kinds(untraced)
    assert "DIVISION_BY_ZERO" in _issue_kinds(traced)
    assert traced.paths_explored == untraced.paths_explored
