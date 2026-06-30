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

"""Shared executor entrypoint collaborator record."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.analysis.detectors.detector.contract import Detector
    from pysymex._internal.analysis.runtime.cache.memory import LRUCache
    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.results.result import ExecutionResult
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.execution.strategies.merger.state import StateMerger
    from pysymex._internal.limits.tracker import ResourceTracker
    from pysymex._internal.typing.protocols import SolverProtocol


@dataclass(frozen=True, slots=True)
class EntrypointInputs:
    """Executor-owned collaborators needed by direct entrypoint owners."""

    config: ExecutionConfig
    solver: SolverProtocol
    session: ExecutionSession
    dispatcher: OpcodeDispatcher
    interaction_graph: ConstraintInteractionGraph
    infrastructure_degraded_passes: list[str]
    state_merger: StateMerger | None
    resource_tracker: ResourceTracker | None
    result_cache: LRUCache[str, ExecutionResult] | None
    result_cache_version: int
    active_detectors: list[Detector]
    execute_loop: Callable[[], None]
