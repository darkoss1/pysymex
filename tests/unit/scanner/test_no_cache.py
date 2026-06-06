from __future__ import annotations

import types
from pathlib import Path

from pysymex.core.cache import get_instructions
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.executors import SymbolicExecutor
from pysymex.scanner.file import scan_file


class ConfigObserver:
    """Collect scan executor configs without changing execution behavior."""

    def __init__(self) -> None:
        self.configs: list[ExecutionConfig] = []

    def activate(self, engine: SymbolicExecutor) -> None:
        self.configs.append(engine.config)

    def begin_code(self, code: types.CodeType) -> None:
        _ = code


def test_scan_file_no_cache_disables_executor_and_solver_caches(tmp_path: Path) -> None:
    target = tmp_path / "target.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    if value > 0:\n"
        "        return value + 1\n"
        "    return value - 1\n",
        encoding="utf-8",
    )
    observer = ConfigObserver()

    result = scan_file(
        target,
        use_sandbox=False,
        trace_enabled=False,
        no_cache=True,
        auto_tune=True,
        max_paths=8,
        max_iterations=80,
        execution_observer=observer,
    )

    assert result.error is None
    assert observer.configs
    assert all(not config.enable_caching for config in observer.configs)
    assert all(not config.enable_solver_cache for config in observer.configs)
    assert get_instructions.cache_info().currsize == 0
