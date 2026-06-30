from __future__ import annotations

import dis

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver


def test_execution_context_like_object_registers_hook() -> None:
    class ContextLike:
        def __init__(self) -> None:
            self.instructions: list[dis.Instruction] = []
            self.solver: IncrementalSolver = IncrementalSolver()
            self._paths_explored: int = 0
            self._coverage: set[int] = set()
            self.issues: list[Issue] = []
            self.hooks: dict[str, object] = {}

        def register_hook(self, hook_name: str, handler: object) -> None:
            self.hooks[hook_name] = handler

    ctx = ContextLike()

    def handler() -> None:
        return None

    ctx.register_hook("before_execute", handler)

    assert "before_execute" in ctx.hooks
    assert ctx.hooks["before_execute"] is handler
