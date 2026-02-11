"""
Auto-Tuner for PySpectre Configuration.

Analyzes code complexity to automatically suggest optimal execution parameters.
"""

from __future__ import annotations
import dis
import types
from dataclasses import dataclass
from pyspectre.execution.executor import ExecutionConfig


@dataclass
class CodeComplexity:
    """Metrics for code complexity."""

    instruction_count: int
    branch_count: int
    loop_count: int
    cyclomatic_complexity: int

    @property
    def score(self) -> int:
        """Combined complexity score."""
        return self.instruction_count + (self.branch_count * 5) + (self.loop_count * 10)


class AutoTuner:
    """Analyzes code and suggests configuration."""

    @staticmethod
    def analyze(code: types.CodeType) -> CodeComplexity:
        """Analyze code object for complexity metrics."""
        instructions = list(dis.get_instructions(code))
        count = len(instructions)
        branches = 0
        loops = 0
        for instr in instructions:
            if "JUMP" in instr.opname:
                if "IF" in instr.opname or "FOR" in instr.opname or "WHILE" in instr.opname:
                    branches += 1
                if "BACKWARD" in instr.opname:
                    loops += 1
        cc = 1 + branches
        return CodeComplexity(
            instruction_count=count,
            branch_count=branches,
            loop_count=loops,
            cyclomatic_complexity=cc,
        )

    @staticmethod
    def tune(code: types.CodeType, base_config: ExecutionConfig = None) -> ExecutionConfig:
        """Return an optimized configuration based on code complexity."""
        complexity = AutoTuner.analyze(code)
        config = base_config or ExecutionConfig()
        if complexity.score < 50:
            config.max_paths = 100
            config.timeout_seconds = 10.0
            config.max_iterations = 1000
        elif complexity.score < 200:
            config.max_paths = 5000
            config.timeout_seconds = 60.0
            config.max_iterations = 20000
        else:
            config.max_paths = 50000
            config.timeout_seconds = 600.0
            config.max_iterations = 500000
            config.max_depth = 2000
        if complexity.loop_count > 0:
            config.max_loop_iterations = max(20, min(100, 20 * complexity.loop_count))
        return config
