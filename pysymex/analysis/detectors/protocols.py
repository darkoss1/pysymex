# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Protocol interfaces for the detector subsystem.

Defines structural interfaces that decouple analysis.detectors from
concrete execution layer types.  Execution types implement these
protocols implicitly (structural subtyping), so no circular import
is needed.
"""

from __future__ import annotations

import dis
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, runtime_checkable

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
    def pc(self) -> int:
        """The current program counter (instruction offset)."""
        ...

    @property
    def stack(self) -> Sequence[object]:
        """A read-only view of the operand stack."""
        ...

    @property
    def path_constraints(self) -> Sequence[object]:
        """The sequence of symbolic constraints active on the current path."""
        ...

    @property
    def locals(self) -> Mapping[str, object]:
        """A mapping of local variable names to their symbolic or concrete values."""
        ...

    @property
    def depth(self) -> int:
        """The current execution depth (number of forks or recursive calls)."""
        ...

    def peek(self, offset: int = 0) -> object:
        """Return the value on the stack at the given offset from the top."""
        ...

    def get_local(self, name: str) -> object:
        """Retrieve the value of a local variable by name."""
        ...

    def fork(self) -> StateView:
        """Create a new state view branching from the current one."""
        ...

    def add_constraint(self, constraint: object) -> None:
        """Register a new symbolic constraint on the state's path."""
        ...


@runtime_checkable
class SolverCheck(Protocol):
    """Callable protocol for satisfiability checks passed to detectors."""

    def __call__(
        self,
        constraints: Sequence[object],
        *,
        timeout_ms: int = ...,
    ) -> bool:
        """Check if the provided constraints are satisfiable under a timeout."""
        ...


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
    ) -> object | None:
        """Perform a bug check for the given instruction and state."""
        ...


@runtime_checkable
class ScanReporter(Protocol):
    """Callback protocol for scan progress reporting.

    Implementations live in CLI/reporting layers; scanner core
    depends only on this interface.
    """

    def on_file_start(self, file_path: object) -> None:
        """Called when analysis begins for a new file."""
        ...

    def on_file_done(self, file_path: object, result: object) -> None:
        """Called when analysis completes for a file."""
        ...

    def on_issue(self, issue: dict[str, object]) -> None:
        """Report a detected issue/bug."""
        ...

    def on_error(self, file_path: object, error: str) -> None:
        """Report a fatal error encountered during analysis."""
        ...

    def on_progress(
        self,
        completed: int,
        total: int,
        file_path: object,
        result: object | None,
    ) -> None:
        """Update progress metrics (e.g. for progress bars)."""
        ...

    def on_status(self, message: str) -> None:
        """Update the UI with a status message."""
        ...

    def on_summary(self, results: Sequence[object], total_files: int) -> None:
        """Report the final analysis summary."""
        ...


@runtime_checkable
class ExecutionContextLike(ExecutionContext, Protocol):
    """Backward-compatible alias for :class:`ExecutionContext`.

    New code should use ``ExecutionContext`` from
    ``pysymex.execution.protocols`` directly.
    """

    ...
