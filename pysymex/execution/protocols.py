# pysymex: Python Symbolic Execution & Formal Verification
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

"""Protocol interfaces for the execution subsystem.

Defines structural interfaces that decouple the executor from concrete
analysis and core types.  Analysis code, detector plugins, and
visualisation hooks should depend on these protocols â€” never on the
:class:`SymbolicExecutor` class directly.
"""

from __future__ import annotations

import dis
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pysymex.core.solver.engine import IncrementalSolver

__all__ = [
    "ExecutionContext",
]


@runtime_checkable
class ExecutionContext(Protocol):
    """Read-side structural interface of the symbolic executor.

    Any concrete ``SymbolicExecutor`` satisfies this protocol through
    structural subtyping â€” no inheritance or registration required.

    Consumers (detectors, visualisation plugins, analysis passes) should
    import this protocol instead of depending on
    ``pysymex.execution.executors.core.SymbolicExecutor``.
    """

    _instructions: Sequence[dis.Instruction]

    solver: IncrementalSolver

    _paths_explored: int

    _coverage: set[int]

    _issues: Sequence[object]

    def register_hook(self, hook_name: str, handler: Callable[..., object]) -> None: ...
