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

"""Core execution tracer class and shared state initialization."""

from __future__ import annotations

import linecache
from collections.abc import Callable
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING

from pysymex.tracing.schemas import TracerConfig
from pysymex.tracing.tracer.events import TracerForkPruneMixin
from pysymex.tracing.tracer.events.detector_query import TracerDetectorQueryMixin
from pysymex.tracing.tracer.events.fallback import TracerFallbackMixin
from pysymex.tracing.tracer.events.issue import TracerIssueMixin
from pysymex.tracing.tracer.events.path_feasibility import TracerPathFeasibilityMixin
from pysymex.tracing.tracer.events.scheduler import TracerSchedulerMixin
from pysymex.tracing.tracer.helpers import TraceWriter
from pysymex.tracing.tracer.install import TracerInstallMixin
from pysymex.tracing.tracer.keyframes import TracerKeyframeMixin
from pysymex.tracing.tracer.session import TracerSessionMixin
from pysymex.tracing.tracer.events.solve import TracerSolveMixin
from pysymex.tracing.tracer.steps.snapshots import TracerStepSnapshotMixin
from pysymex.tracing.tracer.steps import TracerStepMixin
from pysymex.tracing.tracer.writing import TracerWritingMixin
from pysymex.tracing.z3.registry import Z3SemanticRegistry
from pysymex.tracing.z3.serializer import Z3Serializer

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class ExecutionTracer(
    TracerSessionMixin,
    TracerInstallMixin,
    TracerStepSnapshotMixin,
    TracerStepMixin,
    TracerForkPruneMixin,
    TracerSolveMixin,
    TracerDetectorQueryMixin,
    TracerPathFeasibilityMixin,
    TracerSchedulerMixin,
    TracerFallbackMixin,
    TracerIssueMixin,
    TracerKeyframeMixin,
    TracerWritingMixin,
):
    """LLM-optimised observability layer for symbolic executor runs.

    Session lifecycle
    ~~~~~~~~~~~~~~~~~
    1. Construct the tracer with a :class:`~pysymex.tracing.schemas.TracerConfig`.
    2. Call :meth:`start_session` (or use as a context manager).
    3. Call :meth:`install` on a :class:`~pysymex.execution.executors.core.SymbolicExecutor`
       **before** ``execute_function`` / ``execute_code`` is called.
    4. Let the executor run.
    5. Call :meth:`end_session` (or exit the context manager) to flush and
       close the JSONL file.  The returned :class:`~pathlib.Path` points to
       the completed trace file.

    Keyframe + Delta strategy
    ~~~~~~~~~~~~~~~~~~~~~~~~~
    * **Deltas** (``step`` events) capture only *what changed* per instruction:
      dispatch latency, stack diff, variable diff, memory diff, and
      (optionally) a new constraint.  They are cheap to write and cheap to replay.
    * **Keyframes** (``keyframe`` events) capture the *full symbolic state*
      at structurally important moments (fork, prune, issue).  They let an
      LLM re-anchor its understanding without replaying all prior deltas.

    Args:
        config: Tracer configuration.  Defaults to :class:`TracerConfig`.
    """

    def __init__(self, config: TracerConfig | None = None) -> None:
        """Initialize session-level tracing infrastructure and registries."""
        self.config: TracerConfig = config if config is not None else TracerConfig.from_env()
        self._registry: Z3SemanticRegistry = Z3SemanticRegistry()
        self._serializer: Z3Serializer = Z3Serializer(self._registry)

        self.lock: Lock = Lock()
        self.file: TraceWriter | None = None
        self._trace_path: Path | None = None
        self.seq: int = 0
        self._delta_buffer: list[str] = []

        self._path_tree: dict[int, int | None] = {}

        self._pre_step_snapshot: (
            tuple[
                list[StackValue],
                dict[str, StackValue],
                dict[str, StackValue],
                dict[int, StackValue],
                int,
            ]
            | None
        ) = None

        self._current_state: VMState | None = None
        self._fallback_line_resolver: Callable[[int], int | None] | None = None
        self._pre_step_started_ns: int | None = None
        self._linecache = linecache
        self._session_source_file: str = "<unknown>"

    @property
    def registry(self) -> Z3SemanticRegistry:
        """The semantic name registry.  Accessible for external pre-registration."""
        return self._registry


__all__ = ["ExecutionTracer"]
