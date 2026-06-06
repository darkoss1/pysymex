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

"""Shadow reconstruction checkpoints for POLAR frontier validation.

Checkpoints keep a compact snapshot behind a POLAR capsule so reconstruction
parity can be tested before compact runtime queueing is allowed. They support
solver-owned certificate evaluation in runtime CEGIS mode, but they do not
schedule work or remove live states directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

import z3

from pysymex.execution.frontier.evidence import detector_obligation_digest, havoc_root_count
from pysymex.execution.frontier.obligations import (
    CapsuleDigest,
    ObligationCapsule,
    build_shadow_capsule,
    capsule_semantic_digest,
    state_structural_hash,
)

if TYPE_CHECKING:
    from pysymex.core.effects.events import WriteEvent
    from pysymex.core.state.branches import BranchChain
    from pysymex.core.state.deferred import DeferredStateIssue
    from pysymex.core.state.record import VMState
    from pysymex.core.state.types import BlockInfo, CallFrame, LoopCounterKey
    from pysymex.typing import StackValue

__all__ = [
    "FrontierCheckpoint",
    "FrontierReconstructionResult",
    "FrontierReconstructionStatus",
    "FrontierStateSnapshot",
    "build_frontier_checkpoint",
]


class FrontierReconstructionStatus(Enum):
    """Outcome of a shadow checkpoint reconstruction attempt."""

    EXACT = "exact"
    DIGEST_MISMATCH = "digest_mismatch"
    SPILL_FORMAT_MISMATCH = "spill_format_mismatch"


@dataclass(frozen=True, slots=True)
class FrontierReconstructionResult:
    """Result of reconstructing a VMState from a shadow checkpoint."""

    status: FrontierReconstructionStatus
    capsule_id: str
    reconstructed_state: "VMState | None" = None
    expected_digest: CapsuleDigest | None = None
    actual_digest: CapsuleDigest | None = None

    @property
    def is_exact(self) -> bool:
        """Return whether reconstruction produced an exact state snapshot."""
        return self.status is FrontierReconstructionStatus.EXACT


@dataclass(frozen=True, slots=True)
class FrontierCheckpoint:
    """Stored compact state snapshot used to validate future POLAR reconstruction."""

    capsule: ObligationCapsule
    _snapshot: "FrontierStateSnapshot"

    @property
    def snapshot(self) -> "FrontierStateSnapshot":
        """Return the compact snapshot owned by this checkpoint."""
        return self._snapshot

    def snapshot_matches_capsule(self) -> bool:
        """Return whether the stored snapshot still matches the capsule digest."""
        return capsule_semantic_digest(self.capsule) == self._snapshot.digest()

    def path_constraints(self) -> "tuple[z3.BoolRef, ...]":
        """Return checkpointed path constraints without materializing a VMState."""
        return self._snapshot.path_constraints

    def structurally_matches(self, other: "FrontierCheckpoint") -> bool:
        """Return whether two live checkpoints are exact structural duplicates.

        This is stricter than matching capsule digests. Digests and
        ``VMState.hash_value()`` are useful indexes, but the dominance owner
        must recheck exact checkpoint facts before certifying removal.
        """
        return (
            self.snapshot_matches_capsule()
            and other.snapshot_matches_capsule()
            and self._snapshot.structurally_matches(other._snapshot)
        )

    def reconstruct(self) -> FrontierReconstructionResult:
        """Return a parity VMState when the compact snapshot still matches the capsule digest."""
        expected_digest = capsule_semantic_digest(self.capsule)
        actual_digest = self._snapshot.digest()
        if not self.snapshot_matches_capsule():
            return FrontierReconstructionResult(
                status=FrontierReconstructionStatus.DIGEST_MISMATCH,
                capsule_id=self.capsule.capsule_id,
                expected_digest=expected_digest,
                actual_digest=actual_digest,
            )
        return FrontierReconstructionResult(
            status=FrontierReconstructionStatus.EXACT,
            capsule_id=self.capsule.capsule_id,
            reconstructed_state=self._snapshot.reconstruct(),
            expected_digest=expected_digest,
            actual_digest=actual_digest,
        )


@dataclass(frozen=True, slots=True)
class FrontierStateSnapshot:
    """Compact digest-visible state facts for shadow checkpoint reconstruction.

    The reconstructed ``VMState`` is a parity artifact, not an executable
    runtime replacement. It preserves the fields currently tracked by shadow
    capsule digests plus the execution metadata needed by fetch, feasibility,
    loop, detector, async, and call/exception dispatch code. It intentionally
    avoids retaining the active full ``VMState`` object in the frontier.
    """

    stack: tuple["StackValue", ...]
    local_vars: tuple[tuple[str, "StackValue"], ...]
    global_vars: tuple[tuple[str, "StackValue"], ...]
    memory: tuple[tuple[int, "StackValue"], ...]
    path_constraints: tuple["z3.BoolRef", ...]
    constraint_atom_ids: tuple[int, ...]
    havoc_live_count: int
    pc: int
    visited_pcs: frozenset[int]
    path_id: int
    depth: int
    state_structural_hash: int
    block_stack: tuple["BlockInfo", ...]
    call_stack: tuple["CallFrame", ...]
    contract_frames: tuple[object, ...]
    current_instructions: tuple[object, ...] | None
    active_exception: "StackValue | None"
    pending_reraise_exception: "StackValue | None"
    deferred_detector_issues: tuple["DeferredStateIssue", ...]
    pending_constraint_count: int
    last_inconclusive_feasibility_len: int
    loop_iterations: tuple[tuple["LoopCounterKey", int], ...]
    loop_counters: tuple[tuple[int, int], ...]
    freed_vars: frozenset[str]
    prev_loop_states: tuple[tuple["LoopCounterKey", "VMState"], ...]
    branch_trace: "BranchChain"
    open_resources: int
    write_events: tuple["WriteEvent", ...]
    pending_kw_names: tuple[str, ...] | None
    current_coro_id: str | None
    awaitable_results: tuple[tuple[int, "StackValue"], ...]

    @classmethod
    def from_state(cls, state: "VMState") -> "FrontierStateSnapshot":
        """Build a compact snapshot from digest-visible ``VMState`` facts."""
        return cls(
            stack=tuple(state.stack),
            local_vars=state.local_vars.sorted_items(),
            global_vars=state.global_vars.sorted_items(),
            memory=state.memory.sorted_items(),
            path_constraints=tuple(state.path_constraints.to_list()),
            constraint_atom_ids=state.path_constraints.sorted_constraint_hashes(),
            havoc_live_count=havoc_root_count(
                (
                    *state.stack,
                    *state.local_vars.values(),
                    *state.global_vars.values(),
                    *state.memory.values(),
                    *((state.active_exception,) if state.active_exception is not None else ()),
                    *(
                        (state.pending_reraise_exception,)
                        if state.pending_reraise_exception is not None
                        else ()
                    ),
                    *state.awaitable_results.values(),
                )
            ),
            pc=state.pc,
            visited_pcs=frozenset(state.visited_pcs),
            path_id=state.path_id,
            depth=state.depth,
            state_structural_hash=state_structural_hash(state),
            block_stack=tuple(state.block_stack),
            call_stack=tuple(state.call_stack),
            contract_frames=tuple(state.contract_frames),
            current_instructions=(
                tuple(state.current_instructions)
                if state.current_instructions is not None
                else None
            ),
            active_exception=state.active_exception,
            pending_reraise_exception=state.pending_reraise_exception,
            deferred_detector_issues=tuple(state.deferred_detector_issues),
            pending_constraint_count=state.pending_constraint_count,
            last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
            loop_iterations=tuple(
                sorted(state.loop_iterations.items(), key=lambda item: repr(item[0]))
            ),
            loop_counters=tuple(sorted(state.loop_counters.items())),
            freed_vars=frozenset(state.freed_vars),
            prev_loop_states=tuple(
                sorted(state.prev_loop_states.items(), key=lambda item: repr(item[0]))
            ),
            branch_trace=state.branch_trace,
            open_resources=state.open_resources,
            write_events=tuple(state.write_events),
            pending_kw_names=state.pending_kw_names,
            current_coro_id=state.current_coro_id,
            awaitable_results=tuple(sorted(state.awaitable_results.items())),
        )

    def digest(self) -> CapsuleDigest:
        """Return the phase-0 capsule digest represented by this snapshot."""
        return (
            self.path_id,
            self.depth,
            self.pc,
            self.state_structural_hash,
            len(self.stack),
            tuple(name for name, _ in self.local_vars),
            tuple(name for name, _ in self.global_vars),
            len(self.memory),
            self.active_exception is not None,
            self.pending_reraise_exception is not None,
            len(self.write_events),
            len(self.deferred_detector_issues),
            detector_obligation_digest(self.deferred_detector_issues),
            0,
            self.havoc_live_count,
            self.constraint_atom_ids,
            self.pending_constraint_count,
            len(self.branch_trace),
            self.estimated_resident_units,
        )

    @property
    def estimated_resident_units(self) -> int:
        """Return the same deterministic size proxy used by shadow capsules."""
        return (
            len(self.stack)
            + len(self.local_vars)
            + len(self.global_vars)
            + len(self.memory)
            + len(self.path_constraints)
            + len(self.branch_trace)
            + len(self.deferred_detector_issues)
            + len(self.write_events)
        )

    def reconstruct(self) -> "VMState":
        """Rebuild a VMState parity artifact from the compact snapshot."""
        from pysymex.core.state.record import VMState

        reconstructed = VMState(
            stack=list(self.stack),
            local_vars=dict(self.local_vars),
            global_vars=dict(self.global_vars),
            path_constraints=list(self.path_constraints),
            pc=self.pc,
            visited_pcs=set(self.visited_pcs),
            memory=dict(self.memory),
            path_id=self.path_id,
            depth=self.depth,
            block_stack=list(self.block_stack),
            call_stack=list(self.call_stack),
            contract_frames=list(self.contract_frames),
            current_instructions=(
                list(self.current_instructions) if self.current_instructions is not None else None
            ),
            active_exception=self.active_exception,
            pending_reraise_exception=self.pending_reraise_exception,
            deferred_detector_issues=list(self.deferred_detector_issues),
            pending_constraint_count=self.pending_constraint_count,
            last_inconclusive_feasibility_len=self.last_inconclusive_feasibility_len,
            loop_iterations=dict(self.loop_iterations),
            loop_counters=dict(self.loop_counters),
            freed_vars=set(self.freed_vars),
            prev_loop_states=dict(self.prev_loop_states),
            branch_trace=self.branch_trace,
            open_resources=self.open_resources,
            write_events=list(self.write_events),
        )
        reconstructed.pending_kw_names = self.pending_kw_names
        reconstructed.current_coro_id = self.current_coro_id
        reconstructed.awaitable_results = dict(self.awaitable_results)
        reconstructed.invalidate_cached_hash()
        return reconstructed

    def structurally_matches(self, other: "FrontierStateSnapshot") -> bool:
        """Return whether ``other`` preserves every checkpoint-visible root."""
        return (
            self.digest() == other.digest()
            and _z3_constraint_multisets_match(self.path_constraints, other.path_constraints)
            and _values_match(self.stack, other.stack)
            and _named_values_match(self.local_vars, other.local_vars)
            and _named_values_match(self.global_vars, other.global_vars)
            and _memory_values_match(self.memory, other.memory)
            and _objects_match(self.block_stack, other.block_stack)
            and _objects_match(self.call_stack, other.call_stack)
            and _objects_match(self.contract_frames, other.contract_frames)
            and _objects_match_optional(self.current_instructions, other.current_instructions)
            and _value_matches(self.active_exception, other.active_exception)
            and _value_matches(self.pending_reraise_exception, other.pending_reraise_exception)
            and _objects_match(self.deferred_detector_issues, other.deferred_detector_issues)
            and self.last_inconclusive_feasibility_len == other.last_inconclusive_feasibility_len
            and self.loop_iterations == other.loop_iterations
            and self.loop_counters == other.loop_counters
            and self.freed_vars == other.freed_vars
            and _previous_loop_states_match(self.prev_loop_states, other.prev_loop_states)
            and _branch_traces_match(self.branch_trace, other.branch_trace)
            and self.open_resources == other.open_resources
            and _objects_match(self.write_events, other.write_events)
            and self.pending_kw_names == other.pending_kw_names
            and self.current_coro_id == other.current_coro_id
            and _awaitable_results_match(self.awaitable_results, other.awaitable_results)
        )


def build_frontier_checkpoint(
    state: "VMState",
    *,
    capsule_id: str | None = None,
    parent_id: str | None = None,
) -> FrontierCheckpoint:
    """Build a compact shadow checkpoint from ``state`` without mutating the active path."""
    capsule = build_shadow_capsule(state, capsule_id=capsule_id, parent_id=parent_id)
    return FrontierCheckpoint(
        capsule=capsule,
        _snapshot=FrontierStateSnapshot.from_state(state),
    )


def _z3_constraint_multisets_match(
    left: tuple["z3.BoolRef", ...],
    right: tuple["z3.BoolRef", ...],
) -> bool:
    """Return whether both constraint collections contain the same exact ASTs."""
    if len(left) != len(right):
        return False
    matched = [False] * len(right)
    for left_constraint in left:
        found = False
        for index, right_constraint in enumerate(right):
            if not matched[index] and z3.eq(left_constraint, right_constraint):
                matched[index] = True
                found = True
                break
        if not found:
            return False
    return True


def _value_matches(left: object, right: object) -> bool:
    """Return whether two checkpoint values are safe exact matches."""
    if left is right:
        return True
    if type(left) is not type(right):
        return False
    if isinstance(left, (bool, int, float, str, bytes, type(None))):
        return left == right
    return False


def _values_match(left: tuple[object, ...], right: tuple[object, ...]) -> bool:
    """Return whether both value sequences have exact checkpoint-visible roots."""
    return len(left) == len(right) and all(
        _value_matches(left_value, right_value)
        for left_value, right_value in zip(left, right, strict=True)
    )


def _named_values_match(
    left: tuple[tuple[str, object], ...],
    right: tuple[tuple[str, object], ...],
) -> bool:
    """Return whether named value tuples match by key and exact value root."""
    return len(left) == len(right) and all(
        left_name == right_name and _value_matches(left_value, right_value)
        for (left_name, left_value), (right_name, right_value) in zip(left, right, strict=True)
    )


def _memory_values_match(
    left: tuple[tuple[int, object], ...],
    right: tuple[tuple[int, object], ...],
) -> bool:
    """Return whether memory cells match by address and exact value root."""
    return len(left) == len(right) and all(
        left_address == right_address and _value_matches(left_value, right_value)
        for (left_address, left_value), (right_address, right_value) in zip(
            left,
            right,
            strict=True,
        )
    )


def _objects_match(left: tuple[object, ...], right: tuple[object, ...]) -> bool:
    """Return whether complex metadata roots are the same objects or simple equals."""
    return _values_match(left, right)


def _objects_match_optional(
    left: tuple[object, ...] | None,
    right: tuple[object, ...] | None,
) -> bool:
    """Return whether optional metadata root tuples match exactly."""
    if left is None or right is None:
        return left is right
    return _objects_match(left, right)


def _branch_traces_match(left: "BranchChain", right: "BranchChain") -> bool:
    """Return whether two branch traces contain the same exact decisions."""
    left_records = left.to_list()
    right_records = right.to_list()
    return len(left_records) == len(right_records) and all(
        left_record.pc == right_record.pc
        and left_record.taken == right_record.taken
        and z3.eq(left_record.condition, right_record.condition)
        for left_record, right_record in zip(left_records, right_records, strict=True)
    )


def _previous_loop_states_match(
    left: tuple[tuple["LoopCounterKey", "VMState"], ...],
    right: tuple[tuple["LoopCounterKey", "VMState"], ...],
) -> bool:
    """Return whether previous loop-state references match exactly."""
    return len(left) == len(right) and all(
        left_key == right_key and left_state is right_state
        for (left_key, left_state), (right_key, right_state) in zip(left, right, strict=True)
    )


def _awaitable_results_match(
    left: tuple[tuple[int, object], ...],
    right: tuple[tuple[int, object], ...],
) -> bool:
    """Return whether awaitable result roots match by ID and exact value."""
    return len(left) == len(right) and all(
        left_id == right_id and _value_matches(left_value, right_value)
        for (left_id, left_value), (right_id, right_value) in zip(left, right, strict=True)
    )
