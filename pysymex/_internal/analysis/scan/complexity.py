# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Bytecode complexity analysis and execution-config tuning.

Analyzes a ``CodeType`` to produce structural complexity metrics (branch,
loop, call, and instruction counts) and a weighted composite score.
The score drives heuristics that adjust solver timeouts and
``ExecutionConfig`` parameters (path limits, iteration caps, depth) so
that simple functions run cheaply and complex functions receive more
resources.

This module does not invoke the solver or execute bytecode; it only
inspects opcode names.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, TypeVar

from pysymex._internal.core.bytecode import CALL_OPCODES
from pysymex._internal.core.cache.code.instructions import get_instructions

if TYPE_CHECKING:
    from types import CodeType

    from pysymex._internal.config.execution.settings import ExecutionConfig


@dataclass(frozen=True, slots=True)
class ComplexityMetrics:
    """Structural complexity metrics for a single code object.

    The ``score`` is computed as::

        branch_count * 3 + loop_count * 5 + call_count * 2 + instruction_count // 10
    """

    instruction_count: int
    branch_count: int
    loop_count: int
    call_count: int
    score: int


BRANCH_OPS = frozenset(
    (
        "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_IF_NONE",
        "POP_JUMP_IF_NOT_NONE",
        "POP_JUMP_FORWARD_IF_TRUE",
        "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_FORWARD_IF_NONE",
        "POP_JUMP_FORWARD_IF_NOT_NONE",
        "POP_JUMP_BACKWARD_IF_TRUE",
        "POP_JUMP_BACKWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_NONE",
        "POP_JUMP_BACKWARD_IF_NOT_NONE",
        "JUMP_IF_TRUE_OR_POP",
        "JUMP_IF_FALSE_OR_POP",
    ),
)
BACKWARD_OPS = frozenset(("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"))
LOOP_OPS = frozenset(("FOR_ITER", "GET_ITER"))
CALL_OPS = CALL_OPCODES


def analyze_complexity(code: CodeType) -> ComplexityMetrics:
    """Compute structural complexity metrics for *code*.

    Iterates through the bytecode instructions once, classifying each
    opcode as a branch, loop, or call operation and counting totals.

    Args:
        code: The compiled code object to analyze.

    Returns:
        A ``ComplexityMetrics`` instance with counts and composite score.

    """
    instrs = get_instructions(code)
    branch_count = 0
    loop_count = 0
    call_count = 0
    total_instrs = len(instrs)

    for instr in instrs:
        if instr.opname in BRANCH_OPS:
            branch_count += 1
        elif instr.opname in BACKWARD_OPS or instr.opname in LOOP_OPS:
            loop_count += 1
        elif instr.opname in CALL_OPS:
            call_count += 1

            # Weighted score calculation
    score = branch_count * 3 + loop_count * 5 + call_count * 2 + total_instrs // 10

    return ComplexityMetrics(
        instruction_count=total_instrs,
        branch_count=branch_count,
        loop_count=loop_count,
        call_count=call_count,
        score=score,
    )


def recommended_timeout_ms(score: int) -> int:
    """Map a complexity score to a solver timeout in milliseconds.

    Breakpoints: ≤10 → 2 s, ≤30 → 5 s, ≤60 → 10 s, ≤100 → 20 s,
    >100 → min(60 s, score × 300 ms).

    Args:
        score: The weighted complexity score from ``analyze_complexity``.

    Returns:
        Recommended solver timeout in milliseconds.

    """
    if score <= 10:
        timeout_ms = 2000
    elif score <= 30:
        timeout_ms = 5000
    elif score <= 60:
        timeout_ms = 10000
    elif score <= 100:
        timeout_ms = 20000
    else:
        timeout_ms = min(60000, score * 300)
    return timeout_ms


def tune_execution_config(code: CodeType, base_config: ExecutionConfig) -> ExecutionConfig:
    """Adjust *base_config* resource limits based on bytecode complexity.

    Tunes limits according to a 5-tier complexity score model to balance resource
    spend with precision. Applies tightening for low-complexity cases and
    relaxation with advanced optimization policy overrides for highly complex cases.

    Args:
        code: The compiled code object to analyze.
        base_config: Baseline execution configuration to adjust.

    Returns:
        A new ``ExecutionConfig`` with adjusted limits.

    """
    metrics = analyze_complexity(code)
    config = base_config
    score = metrics.score

    # Multi-tiered configuration scaling based on complexity score
    if score < 15:
        # Low Complexity: Tighten limits heavily to run extremely fast
        config = replace(
            config,
            max_paths=_adjust_limit(config.max_paths, 100),
            timeout_seconds=_adjust_limit(config.timeout_seconds, 10.0),
            max_iterations=_adjust_limit(config.max_iterations, 2000),
        )
    elif score <= 50:
        # Medium-Low Complexity: Tighten limits moderately
        config = replace(
            config,
            max_paths=_adjust_limit(config.max_paths, 500),
            timeout_seconds=_adjust_limit(config.timeout_seconds, 20.0),
            max_iterations=_adjust_limit(config.max_iterations, 5000),
        )
    elif score <= 100:
        # Medium-High Complexity: Match baseline limits
        pass
    elif score <= 200:
        # High Complexity: Relax limits to allow thorough verification
        config = replace(
            config,
            max_paths=_adjust_limit(config.max_paths, 2000),
            timeout_seconds=_adjust_limit(config.timeout_seconds, 60.0),
            max_iterations=_adjust_limit(config.max_iterations, 50000),
            max_depth=_adjust_limit(config.max_depth, 500),
        )
    else:
        # Very High Complexity: Relax limits and enable aggressive merging to combat path explosion
        config = replace(
            config,
            max_paths=_adjust_limit(config.max_paths, 5000),
            timeout_seconds=_adjust_limit(config.timeout_seconds, 120.0),
            max_iterations=_adjust_limit(config.max_iterations, 100000),
            max_depth=_adjust_limit(config.max_depth, 1000),
            merge_policy="aggressive",
            lazy_eval_threshold=50,
        )

    # Tune the solver timeout based on code complexity
    tuned_solver_timeout = recommended_timeout_ms(score)
    if config.solver_timeout_ms == 10000:
        config = replace(config, solver_timeout_ms=tuned_solver_timeout)
    else:
        config = replace(config, solver_timeout_ms=min(config.solver_timeout_ms, tuned_solver_timeout))

    if metrics.loop_count > 0:
        candidate = max(10, min(50, 10 * metrics.loop_count))
        config = replace(
            config,
            max_loop_iterations=(
                min(config.max_loop_iterations, candidate)
                if config.max_loop_iterations is not None
                else candidate
            ),
        )

    return config


T = TypeVar("T", int, float)


def _adjust_limit(current: T | None, candidate: T) -> T | None:
    """Adjust an elective resource limit relative to candidate, preserving None."""
    if current is None:
        return None
    return min(current, candidate)
