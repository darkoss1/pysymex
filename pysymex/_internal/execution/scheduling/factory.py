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

"""Path-manager construction for execution scheduling."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.strategies.manager.types import ExplorationStrategy, PathManager

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


def create_path_manager(
    strategy: ExplorationStrategy,
    cig: ConstraintInteractionGraph | None = None,
    frontier_runtime_mode: FrontierRuntimeMode = FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
) -> PathManager[VMState]:
    """Construct the adaptive path manager for symbolic exploration."""
    if strategy is not ExplorationStrategy.ADAPTIVE:
        msg = f"unsupported exploration strategy: {strategy!r}"
        raise ValueError(msg)
    if cig is None:
        from pysymex._internal.core.solver.independence.optimizer import (
            IndependenceOptimizer,
        )

        cig = ConstraintInteractionGraph(IndependenceOptimizer())
    from pysymex._internal.execution.strategies.manager.path import PolarCegisPathManager

    return PolarCegisPathManager(
        cig,
        frontier_runtime_mode=frontier_runtime_mode,
    )
