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

"""Typing contracts for VM state mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pysymex._internal.core.effects.events import WriteEvent
    from pysymex._internal.core.memory.cow.dicts import CowDict
    from pysymex._internal.core.memory.cow.sets import CowSet
    from pysymex._internal.core.solver.constraints.chain import ConstraintChain
    from pysymex._internal.core.state.branches import BranchChain
    from pysymex._internal.core.state.deferred import DeferredStateIssue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import BlockInfo, CallFrame, LoopCounterKey
    from pysymex._internal.typing.protocols import StackValue


class VMStateMixinAttributes(Protocol):
    """Structural contract required by the VM state behavior mixins.

    The protocol describes path-local execution data shared by mutation and
    fork helpers; it does not construct states or own execution semantics.
    """

    stack: list[StackValue]
    local_vars: CowDict[str, StackValue]
    global_vars: CowDict[str, StackValue]
    path_constraints: ConstraintChain
    pc: int
    block_stack: list[BlockInfo]
    call_stack: list[CallFrame]
    contract_frames: list[object]
    visited_pcs: CowSet[int]
    memory: CowDict[int, StackValue]
    path_id: int
    depth: int
    current_instructions: list[object] | None
    active_exception: StackValue | None
    pending_reraise_exception: StackValue | None
    deferred_detector_issues: list[DeferredStateIssue]
    pending_constraint_count: int
    last_inconclusive_feasibility_len: int
    loop_iterations: CowDict[LoopCounterKey, int]
    loop_counters: CowDict[int, int]
    freed_vars: CowSet[str]
    prev_loop_states: CowDict[LoopCounterKey, VMState]
    branch_trace: BranchChain
    open_resources: int
    write_events: list[WriteEvent]
    _cached_hash: int | None
    pending_kw_names: tuple[str, ...] | None
    current_coro_id: str | None
    awaitable_results: dict[int, StackValue]
