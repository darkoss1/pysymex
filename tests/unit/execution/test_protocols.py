from __future__ import annotations

import dis

from pysymex.analysis.detectors.base import Issue
from pysymex.core.solver.engine import ShadowSolver


class TestExecutionContext:
    """Test suite for pysymex.execution.protocols.ExecutionContext."""

    def test_register_hook(self) -> None:
        """Scenario: register a hook by name; expected handler stored at that key."""
        class ContextLike:
            def __init__(self) -> None:
                self._instructions: list[dis.Instruction] = []
                self.solver: ShadowSolver = ShadowSolver()
                self._paths_explored: int = 0
                self._coverage: set[int] = set()
                self._issues: list[Issue] = []
                self.hooks: dict[str, object] = {}

            def register_hook(self, hook_name: str, handler: object) -> None:
                self.hooks[hook_name] = handler

        ctx = ContextLike()

        def handler() -> None:
            return None

        ctx.register_hook("before_execute", handler)

        assert "before_execute" in ctx.hooks
        assert ctx.hooks["before_execute"] is handler