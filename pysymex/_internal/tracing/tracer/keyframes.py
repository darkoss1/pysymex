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

"""Keyframe construction for execution tracers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.config.tracing.settings import TracerConfig, VerbosityLevel
from pysymex._internal.logging.root import get_logger
from pysymex._internal.tracing.schemas.events import KeyframeEvent
from pysymex._internal.tracing.tracer.serialization import TraceSerialization

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.tracing.schemas.primitives import ConstraintEntry
    from pysymex._internal.tracing.z3.serializer import Z3Serializer


logger = get_logger(__name__)


class TracerKeyframeMixin:
    """Keyframe model construction behavior."""

    if TYPE_CHECKING:
        config: TracerConfig
        _serializer: Z3Serializer
        _path_tree: dict[int, int | None]

        def _next_seq(self) -> int:
            """Allocate and return the next event sequence number.

            Returns:
                The next sequential integer identifier.

            """
            ...

    def _build_keyframe(
        self,
        state: VMState,
        trigger: str,
        child_path_ids: list[int] | None,
        prune_reason: str | None,
    ) -> KeyframeEvent:
        """Construct a :class:`~pysymex._internal.tracing.schemas.KeyframeEvent` from *state*."""
        path_id = getattr(state, "path_id", 0)
        parent_path_id = self._path_tree.get(path_id)

        stack_strs: list[str] = []
        try:
            for v in state.stack or []:
                stack_strs.append(self._serializer.serialize_stack_value(v))
        except Exception:
            logger.debug("Failed to serialize keyframe stack", exc_info=True)

        local_strs = self._serializer.serialize_namespace(state.local_vars)
        global_strs: dict[str, str] = {}
        if self.config.verbosity != VerbosityLevel.QUIET:
            global_strs = self._serializer.serialize_namespace(state.global_vars)

        constraint_entries: list[ConstraintEntry] = []
        try:
            pc_val = getattr(state, "pc", 0)
            depth_val = getattr(state, "depth", 0)
            causality = f"path constraint at PC={pc_val}, depth={depth_val}"
            constraints_raw = list(state.path_constraints or [])
            constraint_entries = TraceSerialization.constraint_entries(
                self._serializer,
                constraints_raw,
                causality,
                limit=self.config.max_constraint_display,
            )
        except Exception:
            logger.debug("Failed to serialize keyframe constraints", exc_info=True)

        trigger_val = trigger if trigger in ("fork", "prune", "issue") else "prune"

        return KeyframeEvent(
            seq=self._next_seq(),
            trigger=trigger_val,
            path_id=path_id,
            parent_path_id=parent_path_id,
            child_path_ids=child_path_ids,
            pc=getattr(state, "pc", 0),
            depth=getattr(state, "depth", 0),
            stack=stack_strs,
            local_vars=local_strs,
            global_vars=global_strs,
            path_constraints=constraint_entries,
            prune_reason=prune_reason,
        )
