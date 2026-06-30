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

"""Frontier state snapshot record."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.checkpoint.snapshot.capture import snapshot_from_state
from pysymex._internal.execution.frontier.checkpoint.snapshot.digest import (
    snapshot_digest,
    snapshot_estimated_resident_units,
)
from pysymex._internal.execution.frontier.checkpoint.snapshot.matching import (
    snapshots_structurally_match,
)
from pysymex._internal.execution.frontier.checkpoint.snapshot.reconstruction import (
    reconstruct_snapshot,
)

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.effects.events import WriteEvent
    from pysymex._internal.core.state.branches import BranchChain
    from pysymex._internal.core.state.deferred import DeferredStateIssue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import BlockInfo, CallFrame, LoopCounterKey
    from pysymex._internal.execution.frontier.obligations.types import CapsuleDigest
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class FrontierStateSnapshot:
    """Compact digest-visible state facts for shadow checkpoint reconstruction."""

    stack: tuple[StackValue, ...]
    local_vars: tuple[tuple[str, StackValue], ...]
    global_vars: tuple[tuple[str, StackValue], ...]
    memory: tuple[tuple[int, StackValue], ...]
    path_constraints: tuple[z3.BoolRef, ...]
    constraint_atom_ids: tuple[int, ...]
    havoc_live_count: int
    pc: int
    visited_pcs: frozenset[int]
    path_id: int
    depth: int
    state_structural_hash: int
    block_stack: tuple[BlockInfo, ...]
    call_stack: tuple[CallFrame, ...]
    contract_frames: tuple[object, ...]
    current_instructions: tuple[object, ...] | None
    active_exception: StackValue | None
    pending_reraise_exception: StackValue | None
    deferred_detector_issues: tuple[DeferredStateIssue, ...]
    pending_constraint_count: int
    last_inconclusive_feasibility_len: int
    loop_iterations: tuple[tuple[LoopCounterKey, int], ...]
    loop_counters: tuple[tuple[int, int], ...]
    freed_vars: frozenset[str]
    prev_loop_states: tuple[tuple[LoopCounterKey, VMState], ...]
    branch_trace: BranchChain
    open_resources: int
    write_events: tuple[WriteEvent, ...]
    pending_kw_names: tuple[str, ...] | None
    current_coro_id: str | None
    awaitable_results: tuple[tuple[int, StackValue], ...]
    _estimated_resident_units: int = field(init=False, repr=False, compare=False)
    _digest: CapsuleDigest = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Cache immutable digest facts used repeatedly during frontier matching."""
        estimated_resident_units = snapshot_estimated_resident_units(self)
        object.__setattr__(self, "_estimated_resident_units", estimated_resident_units)
        object.__setattr__(
            self,
            "_digest",
            snapshot_digest(self, estimated_resident_units=estimated_resident_units),
        )

    @classmethod
    def from_state(cls, state: VMState) -> FrontierStateSnapshot:
        """Build a compact snapshot from digest-visible ``VMState`` facts."""
        return snapshot_from_state(cls, state)

    def digest(self) -> CapsuleDigest:
        """Return the phase-0 capsule digest represented by this snapshot."""
        return self._digest

    @property
    def estimated_resident_units(self) -> int:
        """Return the same deterministic size proxy used by shadow capsules."""
        return self._estimated_resident_units

    def reconstruct(self) -> VMState:
        """Rebuild a VMState parity artifact from the compact snapshot."""
        return reconstruct_snapshot(self)

    def structurally_matches(self, other: FrontierStateSnapshot) -> bool:
        """Return whether ``other`` preserves every checkpoint-visible root."""
        return snapshots_structurally_match(self, other)
