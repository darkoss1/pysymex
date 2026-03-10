"""
Auto-Tuner for PySyMex Configuration.

Analyzes code complexity to automatically suggest optimal execution parameters.
"""

from __future__ import annotations

import types
from dataclasses import dataclass, replace

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions
from pysymex.execution.executor import ExecutionConfig


@dataclass(frozen=True, slots=True)
class CodeComplexity:
    """Metrics for code complexity."""

    instruction_count: int
    branch_count: int
    loop_count: int
    cyclomatic_complexity: int

    @property
    def score(self) -> int:
        """Combined complexity score incorporating all metrics."""
        return self.instruction_count + (self.branch_count * 5) + (self.loop_count * 10)


class AutoTuner:
    """Analyzes code and suggests configuration."""

    SCORE_LOW = 50
    SCORE_HIGH = 200

    @staticmethod
    def analyze(code: types.CodeType) -> CodeComplexity:
        """Analyze code object for complexity metrics."""
        instructions = list(_cached_get_instructions(code))
        branches = 0
        loops = 0

        for instr in instructions:
            op = instr.opname
            argval = getattr(instr, "argval", None)
            offset = getattr(instr, "offset", 0)

            if "IF" in op or "FOR" in op:
                branches += 1

            if (
                "FOR" in op
                or "BACKWARD" in op
                or ("ABSOLUTE" in op and isinstance(argval, int) and argval < offset)
            ):
                loops += 1

        return CodeComplexity(
            instruction_count=len(instructions),
            branch_count=branches,
            loop_count=loops,
            cyclomatic_complexity=1 + branches,
        )

    @staticmethod
    def tune(code: types.CodeType, base_config: ExecutionConfig | None = None) -> ExecutionConfig:
        """Return an optimized configuration based on code complexity."""
        complexity = AutoTuner.analyze(code)
        config = base_config or ExecutionConfig()

        if complexity.score < AutoTuner.SCORE_LOW:

            config = replace(
                config,
                max_paths=min(config.max_paths, 100),
                timeout_seconds=min(config.timeout_seconds, 10.0),
                max_iterations=min(config.max_iterations, 2000),
            )
        elif complexity.score < AutoTuner.SCORE_HIGH:

            pass
        else:

            config = replace(
                config,
                max_paths=max(config.max_paths, 2000),
                timeout_seconds=max(config.timeout_seconds, 60.0),
                max_iterations=max(config.max_iterations, 50000),
                max_depth=max(config.max_depth, 500),
            )

        if complexity.loop_count > 0:
            config = replace(
                config,
                max_loop_iterations=max(10, min(50, 10 * complexity.loop_count)),
            )

        return config
