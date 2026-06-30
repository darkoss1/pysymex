from __future__ import annotations

import types
from pathlib import Path

from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.scanner.file import scan_file


class _Observer:
    def __init__(self) -> None:
        self.activated = 0
        self.code_names: list[str] = []

    def activate(self, engine: SymbolicExecutor) -> None:
        self.activated += 1

    def begin_code(self, code: types.CodeType) -> None:
        self.code_names.append(code.co_name)


def test_scan_file_observer_tracks_canonical_auto_tuned_execution(tmp_path: Path) -> None:
    target = tmp_path / "observed.py"
    target.write_text("def target(value: int) -> int:\n    return 1 // value\n", encoding="utf-8")
    observer = _Observer()

    result = scan_file(
        target,
        auto_tune=True,
        use_sandbox=False,
        trace_enabled=False,
        execution_observer=observer,
    )

    assert result.error is None
    assert "target" in observer.code_names
    assert observer.activated >= 2
