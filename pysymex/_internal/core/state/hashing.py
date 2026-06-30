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

"""Structural hash construction for VM state deduplication."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.state.types import structural_hash_or_none
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.core.state.mixin.types import VMStateMixinAttributes

logger = get_logger(__name__)
_MASK_64 = 0xFFFFFFFFFFFFFFFF


def compute_state_hash_value(state: VMStateMixinAttributes) -> int:
    """Compute a structural summary used for state deduplication.

    Notes:
        The summary covers selected stacks, stores, constraints, exceptions,
        detector-deferment sites, and loop bookkeeping. It is not a
        semantic-equivalence or path-feasibility proof.

    """
    h = state.pc * 2654435761
    h ^= state.path_constraints.hash_value() * 999999937

    for frame in state.call_stack:
        h = (h * 1000003) ^ frame.hash_value()

    for frame in state.contract_frames:
        h = (h * 1000003) ^ hash(repr(frame))

    for block in state.block_stack:
        h = (h * 1000003) ^ block.hash_value()

    for deferred in state.deferred_detector_issues:
        h = (h * 1000003) ^ hash(deferred.site_key)

    if state.active_exception is not None:
        h = (h * 1000003) ^ hash(repr(state.active_exception))
    if state.pending_reraise_exception is not None:
        h = (h * 1000003) ^ hash(repr(state.pending_reraise_exception))

    h ^= state.local_vars.hash_value() * 31
    h ^= state.global_vars.hash_value() * 1000003
    h ^= state.memory.hash_value() * 82520
    h ^= state.visited_pcs.hash_value() * 12345
    h ^= state.loop_iterations.hash_value() * 131
    h ^= state.loop_counters.hash_value() * 137
    h ^= state.freed_vars.hash_value() * 139
    h ^= state.prev_loop_states.hash_value() * 149
    for event in state.write_events:
        h = (h * 1000003) ^ hash(event)

    for value in state.stack:
        if isinstance(value, SymbolicValue):
            cached_hash = value._hash_cache  # pyright: ignore[reportPrivateUsage]
            value_hash = cached_hash if cached_hash is not None else value.hash_value()
        else:
            value_hash = structural_hash_or_none(value)
            if value_hash is None:
                if logger.state.debug_enabled:
                    logger.debug("Unhashable VM stack value while hashing state")
                value_hash = 0
        h = (h * 31) ^ value_hash

    return h & _MASK_64
