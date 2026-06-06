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

"""Path-exploration scheduling and join-point state merging for symbolic execution.

- :mod:`pysymex.execution.strategies.manager` chooses the next ``VMState`` to explore
  through the POLAR runtime queue.
- :mod:`pysymex.execution.strategies.merger` optionally merges compatible states at
  control-flow joins to reduce path explosion.

The path-manager factory lives in :mod:`pysymex.execution.scheduling`. State-merger factory
helpers remain here while merger ownership is still under ``strategies``.
"""

from pysymex.execution.strategies.manager.path import (
    AdaptivePathManager,
    PolarCegisPathManager,
)
from pysymex.execution.strategies.manager.types import ExplorationStrategy, PathManager
from pysymex.execution.strategies.merger.factory import create_state_merger
from pysymex.execution.strategies.merger.state import StateMerger
from pysymex.execution.strategies.merger.types import MergePolicy, MergeStatistics

__all__ = [
    "AdaptivePathManager",
    "ExplorationStrategy",
    "MergePolicy",
    "MergeStatistics",
    "PathManager",
    "PolarCegisPathManager",
    "StateMerger",
    "create_state_merger",
]
