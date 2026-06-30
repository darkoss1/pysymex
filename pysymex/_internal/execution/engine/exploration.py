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

"""Initial worklist seeding and pre-analysis for symbolic execution runs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.bytecode import instruction_stream_key
from pysymex._internal.execution.fallback.infrastructure import state_merger_prepass_event
from pysymex._internal.execution.scheduling.factory import create_path_manager
from pysymex._internal.execution.scheduling.loops.detector import LoopDetector
from pysymex._internal.execution.scheduling.loops.widening import LoopWidening
from pysymex._internal.execution.scheduling.telemetry import SchedulerEventSource
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from types import CodeType

    from pysymex._internal.config.execution.settings import ExecutionConfig
    from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession
    from pysymex._internal.execution.strategies.merger.state import StateMerger

logger = get_logger(__name__)


def start_path_exploration(
    *,
    session: ExecutionSession,
    config: ExecutionConfig,
    interaction_graph: ConstraintInteractionGraph,
    state_merger: StateMerger | None,
    initial_state: VMState,
    code: CodeType,
) -> None:
    """Seed the run worklist and configure optional path pre-analysis."""
    session.worklist = create_path_manager(
        config.strategy,
        cig=interaction_graph,
        frontier_runtime_mode=config.frontier_runtime_mode,
    )
    if session.scheduler_event_observers and isinstance(session.worklist, SchedulerEventSource):
        session.worklist.add_scheduler_event_observer(session.record_scheduler_event)
    session.worklist.add_state(initial_state)
    if config.use_loop_analysis:
        session.loop_detector = LoopDetector()
        session.loop_detector.analyze_cfg(session.instructions)
        session.loop_detectors[instruction_stream_key(session.instructions)] = session.loop_detector
        session.loop_widening = LoopWidening()
    if state_merger is not None:
        try:
            state_merger.detect_join_points(session.instructions, code=code)
        except (AttributeError, TypeError, IndexError, ValueError):
            logger.warning("State merger join-point detection failed", exc_info=True)
            session.record_fallback_event(state_merger_prepass_event())
