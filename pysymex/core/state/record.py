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

"""Execution-path state record for the symbolic virtual machine.

This module owns the mutable VM state object that combines operand-stack,
variable-store, constraint-chain, call-frame, and branch-trace data used while
exploring one path. Mutation helpers update that path in place; ``fork()``
creates a child using the copy-on-write and persistent structures implemented
by the state mixins.

Notes:
    This module stores constraints and pending execution metadata. Solver
    feasibility and detector publication remain owned by their respective
    solver and analysis layers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.effects.events import WriteEvent
from pysymex.core.memory.cow.collections import CowDict, CowSet
from pysymex.core.solver.constraints.chain import ConstraintChain
from pysymex.core.state.branches import BranchChain
from pysymex.core.state.deferred import DeferredStateIssue
from pysymex.core.state.fork import VMStateForkMixin
from pysymex.core.state.mutation import VMStateMutationMixin
from pysymex.core.state.types import (
    BlockInfo,
    CallFrame,
    LoopCounterKey,
    wrap_cow_dict,
    wrap_cow_set,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue


class VMState(VMStateMutationMixin, VMStateForkMixin):
    """Mutable execution record for a single symbolic path.

    The state owns the operand stack, path-local stores, constraint and branch
    histories, call and block stacks, pending exception data, and execution
    bookkeeping consumed by the VM.

    Notes:
        ``fork()`` isolates copy-on-write stores and mutable path containers
        while retaining persistent histories and immutable/shared references
        where the implementation does not mutate them. ``hash_value()`` is a
        structural deduplication key, not a path-feasibility decision.
    """

    __slots__ = (
        "active_exception",
        "block_stack",
        "branch_trace",
        "call_stack",
        "contract_frames",
        "current_instructions",
        "deferred_detector_issues",
        "depth",
        "freed_vars",
        "global_vars",
        "last_inconclusive_feasibility_len",
        "local_vars",
        "loop_counters",
        "loop_iterations",
        "memory",
        "open_resources",
        "path_constraints",
        "path_id",
        "pc",
        "pending_constraint_count",
        "pending_kw_names",
        "pending_reraise_exception",
        "prev_loop_states",
        "stack",
        "visited_pcs",
        "write_events",
        "_cached_hash",
        "current_coro_id",
        "awaitable_results",
    )

    def __init__(
        self,
        stack: list[StackValue] | None = None,
        local_vars: dict[str, StackValue] | CowDict[str, StackValue] | None = None,
        global_vars: dict[str, StackValue] | CowDict[str, StackValue] | None = None,
        path_constraints: list[z3.BoolRef] | ConstraintChain | None = None,
        pc: int = 0,
        block_stack: list[BlockInfo] | None = None,
        call_stack: list[CallFrame] | None = None,
        contract_frames: list[object] | None = None,
        visited_pcs: set[int] | CowSet[int] | None = None,
        memory: dict[int, StackValue] | CowDict[int, StackValue] | None = None,
        path_id: int = 0,
        depth: int = 0,
        current_instructions: list[object] | None = None,
        active_exception: StackValue | None = None,
        pending_reraise_exception: StackValue | None = None,
        deferred_detector_issues: list[DeferredStateIssue] | None = None,
        pending_constraint_count: int = 0,
        last_inconclusive_feasibility_len: int = -1,
        loop_iterations: dict[LoopCounterKey, int] | CowDict[LoopCounterKey, int] | None = None,
        loop_counters: dict[int, int] | CowDict[int, int] | None = None,
        freed_vars: set[str] | CowSet[str] | None = None,
        prev_loop_states: (
            dict[LoopCounterKey, VMState] | CowDict[LoopCounterKey, VMState] | None
        ) = None,
        branch_trace: BranchChain | None = None,
        open_resources: int | None = None,
        write_events: list[WriteEvent] | None = None,
    ) -> None:
        """Initialize an execution-path state from optional initial data.

        Args:
            stack: Initial operand stack.
            local_vars: Initial local variables, wrapped in a copy-on-write map.
            global_vars: Initial global variables, wrapped in a copy-on-write map.
            path_constraints: Existing persistent chain or initial Z3
                reachability constraints; no satisfiability query is run.
            pc: Initial program counter.
            block_stack: Saved control flow blocks (loops/tries).
            call_stack: Return-path saved states for function calls.
            contract_frames: Active runtime-contract bookkeeping frames.
            visited_pcs: Bytecode offsets already reached on this path.
            memory: Integer-addressed path-local value store.
            path_id: Identifier assigned to this path by the caller.
            depth: Number of symbolic steps taken from the root.
            current_instructions: List of bytecode instructions for the current scope.
            active_exception: Exception currently handled for faithful bare re-raise behavior.
            pending_reraise_exception: Exception escaping from an explicit bare raise.
            deferred_detector_issues: Pending detector emissions copied into
                this state.
            pending_constraint_count: Count of constraints added since the last Z3 check.
            last_inconclusive_feasibility_len: Constraint prefix length of the most recent
                inconclusive path-feasibility check, or ``-1`` when none is active.
            loop_iterations: Tracks iteration counts for loop-bounding.
            loop_counters: Additional per-loop counters used by exploration.
            freed_vars: Names already marked cleared or deleted on this path.
            prev_loop_states: Snapshots of prior loop entry points for state merging.
            branch_trace: Persistent historical record of branch decisions.
            open_resources: Current resource-count metadata for this path.
            write_events: Modeled writes recorded on this path for effect-sensitive analyses.

        Notes:
            This constructor stores constraints and execution metadata; solver
            feasibility and detector publication remain separate operations.
        """
        self._cached_hash = None
        self.stack = stack if stack is not None else []
        self.local_vars = wrap_cow_dict(local_vars)
        self.global_vars = wrap_cow_dict(global_vars)

        if isinstance(path_constraints, ConstraintChain):
            self.path_constraints = path_constraints
        elif path_constraints is not None:
            self.path_constraints = ConstraintChain.from_list(path_constraints)
        else:
            self.path_constraints = ConstraintChain.empty()

        self.pc = pc
        self.block_stack = block_stack if block_stack is not None else []
        self.call_stack = call_stack if call_stack is not None else []
        self.contract_frames = contract_frames if contract_frames is not None else []
        self.visited_pcs = wrap_cow_set(visited_pcs)
        self.memory = wrap_cow_dict(memory)
        self.path_id = path_id
        self.depth = depth
        self.current_instructions = current_instructions
        self.active_exception = active_exception
        self.pending_reraise_exception = pending_reraise_exception
        self.deferred_detector_issues = (
            list(deferred_detector_issues) if deferred_detector_issues is not None else []
        )
        self.pending_constraint_count = pending_constraint_count
        self.last_inconclusive_feasibility_len = last_inconclusive_feasibility_len
        self.loop_iterations = wrap_cow_dict(loop_iterations)
        self.loop_counters = wrap_cow_dict(loop_counters)
        self.freed_vars = wrap_cow_set(freed_vars)
        self.prev_loop_states = wrap_cow_dict(prev_loop_states)
        self.branch_trace = branch_trace if branch_trace is not None else BranchChain.empty()
        self.open_resources = open_resources if open_resources is not None else 0
        self.write_events = list(write_events) if write_events is not None else []
        self.pending_kw_names: tuple[str, ...] | None = None
        self.current_coro_id: str | None = None
        self.awaitable_results: dict[int, StackValue] = {}

    def invalidate_cached_hash(self) -> None:
        """Clear the cached structural hash after direct state mutation."""
        self._cached_hash = None


def known_sat_prefix_len_for_state(state: VMState) -> int:
    """Return the already-proven path-constraint prefix length for a VM state."""
    return max(0, len(state.path_constraints) - state.pending_constraint_count)


__all__ = ["VMState", "known_sat_prefix_len_for_state"]
