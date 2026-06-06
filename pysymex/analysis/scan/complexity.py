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

"""
Bytecode complexity analysis and execution-config tuning.

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
from types import CodeType
from typing import TYPE_CHECKING

from pysymex.core.cache import get_instructions as cached_get_instructions

if TYPE_CHECKING:
    from pysymex.execution.config.settings import ExecutionConfig


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
    {
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
    }
)
BACKWARD_OPS = frozenset({"JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"})
LOOP_OPS = frozenset({"FOR_ITER", "GET_ITER"})
CALL_OPS = frozenset({"CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_KW", "CALL_FUNCTION_EX"})


def analyze_complexity(code: CodeType) -> ComplexityMetrics:
    """Compute structural complexity metrics for *code*.

    Iterates through the bytecode instructions once, classifying each
    opcode as a branch, loop, or call operation and counting totals.

    Args:
        code: The compiled code object to analyze.

    Returns:
        A ``ComplexityMetrics`` instance with counts and composite score.
    """
    instrs = cached_get_instructions(code)
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

    Low-score code (< 15) gets tightened limits; high-score code (> 100)
    gets relaxed limits.  If loops are present, ``max_loop_iterations``
    is set proportionally.

    Does not invoke the solver or execute the code object.

    Args:
        code: The compiled code object to analyze.
        base_config: Baseline execution configuration to adjust.

    Returns:
        A new ``ExecutionConfig`` with adjusted limits.
    """
    metrics = analyze_complexity(code)
    config = base_config

    # Thresholds (calibrated for the new scoring system)
    SCORE_LOW = 15
    SCORE_HIGH = 100

    if metrics.score < SCORE_LOW:
        config = replace(
            config,
            max_paths=min(config.max_paths, 100),
            timeout_seconds=min(config.timeout_seconds, 10.0),
            max_iterations=min(config.max_iterations, 2000),
        )
    elif metrics.score > SCORE_HIGH:
        config = replace(
            config,
            max_paths=max(config.max_paths, 2000),
            timeout_seconds=max(config.timeout_seconds, 60.0),
            max_iterations=max(config.max_iterations, 50000),
            max_depth=max(config.max_depth, 500),
        )

    if metrics.loop_count > 0:
        config = replace(
            config,
            max_loop_iterations=max(10, min(50, 10 * metrics.loop_count)),
        )

    return config
