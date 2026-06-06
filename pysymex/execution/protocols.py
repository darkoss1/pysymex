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

"""Structural read-side contracts exposed by execution components."""

from __future__ import annotations

import dis
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pysymex.typing import SolverProtocol


@runtime_checkable
class ExecutionContext(Protocol):
    """Required executor attributes and hook-registration surface for consumers.

    Defines the structural read-side contract and interface exposed by the symbolic
    executor to other execution and analysis components, including path managers,
    detectors, and runtime models.

    Attributes:
        instructions: Active sequence of compiled CPython instructions.
        solver: The solver instance used to track path constraints.
        _paths_explored: Count of execution paths fully explored.
        _coverage: Set of bytecode instruction offsets covered by execution.
        issues: Captured issues/errors detected during analysis.
    """

    instructions: Sequence[dis.Instruction]

    solver: SolverProtocol

    _paths_explored: int

    _coverage: set[int]

    issues: Sequence[object]

    def register_hook(self, hook_name: str, handler: Callable[..., object]) -> None:
        """Register a callback handler for an executor lifecycle hook.

        Args:
            hook_name: The name of the lifecycle hook (e.g., "before_dispatch", "after_dispatch").
            handler: The callback callable to trigger when the hook event occurs.
        """
        ...
