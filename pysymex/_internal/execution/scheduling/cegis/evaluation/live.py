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

"""Deterministic live frontier views for shadow CEGIS evaluation."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.obligations.types import ObligationCapsule

CheckpointLoader = Callable[[int], FrontierCheckpoint | None]


def find_live_capsule_state_id(
    capsule_id: str,
    *,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
) -> int | None:
    """Return the deterministic live state ID for ``capsule_id`` when present."""
    live_ids = frozenset(live_state_ids)
    for state_id, capsule in sorted(capsules_by_state_id.items()):
        if state_id in live_ids and capsule.capsule_id == capsule_id:
            return state_id
    return None


def live_capsules(
    *,
    live_state_ids: Iterable[int],
    capsules_by_state_id: Mapping[int, ObligationCapsule],
) -> tuple[ObligationCapsule, ...]:
    """Return live capsules in deterministic state-ID order."""
    live_ids = frozenset(live_state_ids)
    return tuple(
        capsule
        for state_id, capsule in sorted(capsules_by_state_id.items())
        if state_id in live_ids
    )


def live_checkpoints(
    *,
    live_state_ids: Iterable[int],
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: CheckpointLoader | None = None,
) -> tuple[FrontierCheckpoint, ...]:
    """Return live checkpoints in deterministic state-ID order."""
    live_ids = frozenset(live_state_ids)
    checkpoints: list[FrontierCheckpoint] = []
    for state_id in sorted(live_ids):
        checkpoint = checkpoint_for_state(
            state_id,
            checkpoints_by_state_id=checkpoints_by_state_id,
            checkpoint_loader=checkpoint_loader,
        )
        if checkpoint is not None:
            checkpoints.append(checkpoint)
    return tuple(checkpoints)


def checkpoint_for_state(
    state_id: int,
    *,
    checkpoints_by_state_id: Mapping[int, FrontierCheckpoint],
    checkpoint_loader: CheckpointLoader | None,
) -> FrontierCheckpoint | None:
    """Return an existing checkpoint or lazily request one for exact owner evidence."""
    checkpoint = checkpoints_by_state_id.get(state_id)
    if checkpoint is not None or checkpoint_loader is None:
        return checkpoint
    return checkpoint_loader(state_id)
