"""Protocol interfaces for the execution subsystem.

Defines structural interfaces that decouple the executor from concrete
analysis and core types.  Analysis code, detector plugins, and
visualisation hooks should depend on these protocols — never on the
:class:`SymbolicExecutor` class directly.
"""

from __future__ import annotations

import dis
from collections.abc import Callable, Sequence
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "ExecutionContext",
]


@runtime_checkable
class ExecutionContext(Protocol):
    """Read-side structural interface of the symbolic executor.

    Any concrete ``SymbolicExecutor`` satisfies this protocol through
    structural subtyping — no inheritance or registration required.

    Consumers (detectors, visualisation plugins, analysis passes) should
    import this protocol instead of depending on
    ``pysymex.execution.executor_core.SymbolicExecutor``.
    """

    _instructions: Sequence[dis.Instruction]

    solver: Any

    _paths_explored: int

    _coverage: set[int]

    _issues: Sequence[object]

    def register_hook(self, hook_name: str, handler: Callable[..., object]) -> None: ...
