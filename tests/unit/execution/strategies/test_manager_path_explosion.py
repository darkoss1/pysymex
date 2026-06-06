from __future__ import annotations

from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.frontier import FrontierRuntimeMode
from pysymex.execution.results.result import ExecutionResult


_BRANCH_EXPLOSION_SOURCE = """
def branch_explosion(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int) -> int:
    score = 0
    if a > 0:
        score += 1
    else:
        score -= 1
    if b > 0:
        score += 2
    else:
        score -= 2
    if c > 0:
        score += 3
    else:
        score -= 3
    if d > 0:
        score += 4
    else:
        score -= 4
    if e > 0:
        score += 5
    else:
        score -= 5
    if f > 0:
        score += 6
    else:
        score -= 6
    if g > 0:
        score += 7
    else:
        score -= 7
    if h > 0:
        score += 8
    else:
        score -= 8
    return score
"""


def test_native_runtime_handles_path_explosion_cap_deterministically() -> None:
    """Default native ordering drives many paths to completion under a path cap."""
    native_result = _execute_branch_explosion(
        FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )

    assert native_result.paths_explored == 65
    assert native_result.paths_completed == 60
    assert native_result.solver_stats["queries"] == 128
    assert native_result.degraded_passes == ["resource_limit_paths"]


def _execute_branch_explosion(mode: FrontierRuntimeMode) -> ExecutionResult:
    namespace: dict[str, object] = {}
    exec(compile(_BRANCH_EXPLOSION_SOURCE, "<path-explosion-cap>", "exec"), namespace)
    target = namespace["branch_explosion"]
    assert callable(target)

    config = ExecutionConfig(
        max_paths=64,
        max_depth=256,
        max_iterations=50000,
        timeout_seconds=30.0,
        enable_cross_function=False,
        enable_type_inference=False,
        enable_fp_filtering=False,
        deterministic_mode=False,
        random_seed=7,
        frontier_runtime_mode=mode,
    )
    return SymbolicExecutor(config).execute_function(
        target,
        symbolic_args={name: "int" for name in "abcdefgh"},
    )
