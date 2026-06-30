"""Runtime parity tests for phase-0 POLAR shadow capsules."""

from __future__ import annotations

from typing import cast

import pytest

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode


@pytest.mark.parametrize(
    ("source", "symbolic_vars"),
    [
        (
            "if x:\n    y = 1\nelse:\n    y = 2\n",
            {"x": "int"},
        ),
        (
            "items = [x]\nif x:\n    items.append(1)\nelse:\n    items.append(2)\ny = len(items)\n",
            {"x": "int"},
        ),
        (
            "try:\n    y = 10 // x\nexcept ZeroDivisionError:\n    y = 0\n",
            {"x": "int"},
        ),
    ],
)
def test_shadow_capsule_digests_match_runtime_states(
    source: str,
    symbolic_vars: dict[str, str],
) -> None:
    """Shadow capsules stay in parity across representative real execution paths."""
    executor = SymbolicExecutor(
        ExecutionConfig(
            max_paths=16,
            max_iterations=200,
            timeout_seconds=5.0,
            frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_SHADOW,
        )
    )
    code = compile(source, "<shadow-runtime-parity>", "exec")

    result = executor.execute_code(code, symbolic_vars, {})

    assert result.paths_explored >= 1
    worklist_stats = cast("dict[str, object]", result.solver_stats["worklist"])
    shadow_frontier = cast("dict[str, object]", worklist_stats["shadow_frontier"])
    assert worklist_stats["frontier_mode"] == FrontierRuntimeMode.POLAR_CEGIS_SHADOW.value
    assert shadow_frontier["enabled"] is True
    assert shadow_frontier["capsule_digest_mismatch_count"] == 0
    assert shadow_frontier["reconstruction_mismatch_count"] == 0
