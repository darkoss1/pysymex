"""Protocol interfaces for the detector subsystem.

Defines structural interfaces that decouple analysis.detectors from
concrete execution layer types.  Execution types implement these
protocols implicitly (structural subtyping), so no circular import
is needed.
"""

from __future__ import annotations

import dis
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from pysymex.execution.protocols import ExecutionContext

__all__ = [
    "DetectorLike",
    "ExecutionContext",
    "ExecutionContextLike",
    "ScanReporter",
    "SolverCheck",
    "StateView",
]


@runtime_checkable
class StateView(Protocol):
    """Read-only view of VM state consumed by detectors.

    Any concrete ``VMState`` satisfies this protocol without
    inheriting from it — structural subtyping only.
    """

    @property
    def pc(self) -> int: ...

    @property
    def stack(self) -> Sequence[object]: ...

    @property
    def path_constraints(self) -> Sequence[object]: ...

    @property
    def locals(self) -> Mapping[str, Any]: ...

    @property
    def depth(self) -> int: ...

    def peek(self, offset: int = 0) -> object: ...

    def get_local(self, name: str) -> object: ...

    def fork(self) -> StateView: ...

    def add_constraint(self, constraint: object) -> None: ...


@runtime_checkable
class SolverCheck(Protocol):
    """Callable protocol for satisfiability checks passed to detectors."""

    def __call__(
        self,
        constraints: Sequence[object],
        *,
        timeout_ms: int = ...,
    ) -> bool: ...


@runtime_checkable
class DetectorLike(Protocol):
    """Structural interface for bug detectors.

    Matches ``Detector`` ABC in ``base.py`` without requiring
    a concrete import.
    """

    name: str
    description: str

    def check(
        self,
        state: StateView,
        instruction: dis.Instruction,
        _solver_check: Callable[..., object],
    ) -> object | None: ...


@runtime_checkable
class ScanReporter(Protocol):
    """Callback protocol for scan progress reporting.

    Implementations live in CLI/reporting layers; scanner core
    depends only on this interface.
    """

    def on_file_start(self, file_path: object) -> None: ...

    def on_file_done(self, file_path: object, result: object) -> None: ...

    def on_issue(self, issue: dict[str, object]) -> None: ...

    def on_error(self, file_path: object, error: str) -> None: ...

    def on_progress(
        self,
        completed: int,
        total: int,
        file_path: object,
        result: object | None,
    ) -> None: ...

    def on_status(self, message: str) -> None: ...

    def on_summary(self, results: Sequence[object], total_files: int) -> None: ...


@runtime_checkable
class ExecutionContextLike(ExecutionContext, Protocol):
    """Backward-compatible alias for :class:`ExecutionContext`.

    New code should use ``ExecutionContext`` from
    ``pysymex.execution.protocols`` directly.
    """

    ...
