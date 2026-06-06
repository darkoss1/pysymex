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

"""Fork and prune keyframe emission behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel

from pysymex.tracing.schemas import TracerConfig

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.executors.core import SymbolicExecutor
    from pysymex.tracing.schemas import KeyframeEvent


class TracerForkPruneMixin:
    """Fork and prune keyframe emission behavior."""

    if TYPE_CHECKING:
        config: TracerConfig
        _path_tree: dict[int, int | None]

        def _build_keyframe(
            self,
            state: VMState,
            trigger: str,
            child_path_ids: list[int] | None,
            prune_reason: str | None,
        ) -> KeyframeEvent:
            """Construct a keyframe snapshot representing a point in execution.

            Args:
                state: The current virtual machine state.
                trigger: The event that triggered the keyframe.
                child_path_ids: Child path IDs if the trigger was a fork.
                prune_reason: The reason for pruning if the trigger was prune.

            Returns:
                A populated KeyframeEvent object.
            """
            ...

        def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
            """Write a telemetry event to the trace output buffer.

            Args:
                event: The event payload model to write.
                force_flush: Whether to flush the output file immediately.
            """
            ...

    def on_fork(
        self,
        executor: SymbolicExecutor,
        parent_state: VMState,
        child_states: list[VMState],
    ) -> None:
        """Emit a keyframe snapshot when a path forks.

        Args:
            executor:      The running executor.
            parent_state:  The state from which the fork originates.
            child_states:  The new child states that were added to the worklist.
        """
        if not self.config.enabled:
            return
        if not self.config.keyframe_on_fork:
            return

        parent_id = getattr(parent_state, "path_id", 0)
        child_ids = [getattr(c, "path_id", 0) for c in child_states]

        for cid in child_ids:
            self._path_tree[cid] = parent_id

        event = self._build_keyframe(
            state=parent_state,
            trigger="fork",
            child_path_ids=child_ids,
            prune_reason=None,
        )
        self._write_event(event, force_flush=True)

    def on_prune(
        self,
        executor: SymbolicExecutor,
        state: VMState,
        reason: str,
    ) -> None:
        """Emit a keyframe snapshot when a path is pruned.

        Args:
            executor: The running executor.
            state:    The pruned state.
            reason:   Short string identifying the prune cause
                      (e.g. ``"infeasible"``, ``"resource_limit"``,
                      ``"duplicate_state"``).
        """
        if not self.config.enabled:
            return
        if not self.config.keyframe_on_prune:
            return

        event = self._build_keyframe(
            state=state,
            trigger="prune",
            child_path_ids=None,
            prune_reason=reason,
        )
        self._write_event(event, force_flush=True)


__all__ = ["TracerForkPruneMixin"]
