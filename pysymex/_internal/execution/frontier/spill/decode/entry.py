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

"""File loading boundary for frontier spill materialization."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.checkpoints import FrontierReconstructionStatus
from pysymex._internal.execution.frontier.entries import (
    FrontierMaterializationError,
    FrontierQueueEntry,
)
from pysymex._internal.execution.frontier.spill.fields.decode import object_payload

from .state import state_from_spill_payload

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


def realize_spilled_frontier_entry(entry: FrontierQueueEntry) -> VMState:
    """Load and reconstruct a VMState from a spilled compact checkpoint entry."""
    spill_file = entry.spilled_checkpoint_path
    if spill_file is None:
        msg = "frontier entry is not spilled"
        raise ValueError(msg)
    try:
        with spill_file.open("r", encoding="utf-8") as handle:
            raw_payload: object = json.load(handle)
    except OSError as exc:
        raise FrontierMaterializationError(
            capsule_id=str(spill_file),
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        ) from exc

    payload = object_payload(raw_payload)
    if payload is None:
        raise FrontierMaterializationError(
            capsule_id=str(spill_file),
            status=FrontierReconstructionStatus.SPILL_FORMAT_MISMATCH,
        )
    return state_from_spill_payload(payload)
