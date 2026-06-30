from __future__ import annotations

import types
from pathlib import Path

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.execution.scan.setup import build_scan_execution_setup
from pysymex._internal.scanner.file import scan_file


class ConfigObserver:
    """Collect scan executor configs without changing execution behavior."""

    def __init__(self) -> None:
        self.configs: list[ExecutionConfig] = []

    def activate(self, engine: SymbolicExecutor) -> None:
        self.configs.append(engine.config)

    def begin_code(self, code: types.CodeType) -> None:
        _ = code


def test_scan_execution_config_disables_discarded_static_prepasses() -> None:
    observer = ConfigObserver()

    setup = build_scan_execution_setup(
        max_paths=8,
        max_depth=123,
        timeout=5.0,
        no_cache=False,
        max_iterations=80,
        enable_fp_filtering=True,
        execution_observer=observer,
    )

    assert setup.config.enable_cross_function is False
    assert setup.config.max_depth == 123
    assert setup.executor.config is setup.config
    assert observer.configs == [setup.config]


def test_scan_execution_config_preserves_automatic_host_limits() -> None:
    setup = build_scan_execution_setup(
        max_paths=None,
        max_depth=None,
        timeout=None,
        no_cache=False,
        max_iterations=None,
        enable_fp_filtering=True,
    )

    assert setup.config.max_paths is None
    assert setup.config.max_depth is None
    assert setup.config.max_iterations is None
    assert setup.config.timeout_seconds is None


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
