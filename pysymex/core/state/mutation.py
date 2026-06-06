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

"""In-place execution-path state mutation and structural hashing methods."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.effects.events import WriteEvent
from pysymex.core.memory.cow.collections import CowDict
from pysymex.core.state.branches import BranchRecord
from pysymex.core.state._mixin_types import VMStateMixinAttributes
from pysymex.core.state.types import (
    UNBOUND,
    BlockInfo,
    CallFrame,
    LoopCounterKey,
    VMStateError,
    UnboundType,
    structural_hash_or_none,
)
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

logger = get_logger(__name__)


class VMStateMutationMixin(VMStateMixinAttributes):
    """Mutate one execution path's stacks, stores, and constraints in place.

    The helpers invalidate structural hashes when state relevant to
    deduplication changes. Branch creation remains owned by
    :class:`pysymex.core.state.fork.VMStateForkMixin`.

    Notes:
        Helpers that mutate fields included in :meth:`hash_value` clear the
        cached structural summary so duplicate-state pruning cannot compare
        stale stack, store, frame, or block metadata.
    """

    def push(self, value: StackValue) -> VMState:
        """Push *value* onto the operand stack.  Returns ``self``."""
        self.stack.append(value)
        self._cached_hash = None
        return cast("VMState", self)

    def pop(self) -> StackValue:
        """Pop a value from the operand stack.

        Raises:
            VMStateError: If the operand stack is empty.
        """
        if not self.stack:
            logger.warning("VM stack underflow on pop at pc=%s", self.pc)
            raise VMStateError("Stack underflow")
        self._cached_hash = None
        return self.stack.pop()

    def peek(self, n: int = 0) -> StackValue:
        """Return the ``n``-th value from the top without mutating the stack.

        Raises:
            VMStateError: If ``n`` is outside the current operand stack.
        """
        if len(self.stack) <= n:
            logger.warning("VM stack underflow on peek position=%d pc=%s", n, self.pc)
            raise VMStateError(f"Stack underflow: cannot peek at position {n}")
        return self.stack[-(n + 1)]

    def advance_pc(self, delta: int = 1) -> VMState:
        """Increment ``pc`` by *delta*.  Returns ``self``."""
        self.pc += delta
        self._cached_hash = None
        return cast("VMState", self)

    def set_pc(self, target: int) -> VMState:
        """Set ``pc`` to *target*.  Returns ``self``."""
        self.pc = target
        self._cached_hash = None
        return cast("VMState", self)

    def increment_loop_iteration(self, key: LoopCounterKey) -> int:
        """Increment loop iteration count for *key*. Returns new count.

        Invalidates hash to ensure loop detection logic sees the updated state.
        """
        current_count = self.loop_iterations.get(key)
        count = (current_count if current_count is not None else 0) + 1
        self.loop_iterations[key] = count
        self._cached_hash = None
        return count

    def record_freed_var(self, name: str) -> VMState:
        """Mark a variable as freed/deleted. Returns ``self``."""
        if name not in self.freed_vars:
            self.freed_vars.add(name)
            self._cached_hash = None
        return cast("VMState", self)

    def store_heap(self, address: int, value: StackValue) -> VMState:
        """Store a value in symbolic memory at *address*. Returns ``self``.

        Invalidates the cached state hash to ensure correct path deduplication.
        """
        self.memory[address] = value
        self._cached_hash = None
        return cast("VMState", self)

    def load_heap(self, address: int, default: StackValue | None = None) -> StackValue | None:
        """Load a value from symbolic memory at *address*."""
        return self.memory.get(address, default)

    def set_local(self, name: str, value: StackValue | UnboundType) -> VMState:
        """Mutate a local binding and return this state.

        Side Effects:
            ``UNBOUND`` removes any stored local value, records the name as
            freed, and invalidates the cached structural hash.
        """
        if value is UNBOUND:
            if name in self.local_vars:
                del self.local_vars[name]
                self._cached_hash = None
            self.record_freed_var(name)
            return cast("VMState", self)
        self.local_vars[name] = cast("StackValue", value)
        self._cached_hash = None
        return cast("VMState", self)

    def set_global(self, name: str, value: StackValue) -> VMState:
        """Set global variable *name* to *value*.  Returns ``self``."""
        self.global_vars[name] = value
        self._cached_hash = None
        return cast("VMState", self)

    def record_write_event(self, event: WriteEvent) -> VMState:
        """Append a modeled write event for effect-sensitive analyses."""
        self.write_events.append(event)
        self._cached_hash = None
        return cast("VMState", self)

    def add_constraint(self, constraint: z3.BoolRef) -> VMState:
        """Append a path constraint without querying satisfiability.

        Side Effects:
            Replaces the persistent constraint-chain head, increments the
            pending-constraint count for nontrivial constraints, and clears
            the cached structural hash.

        Notes:
            Feasibility checks and any resulting pruning occur in solver or
            exploration owners, not in this mutation helper.
        """
        self.path_constraints = self.path_constraints.append(constraint)
        if not z3.is_true(constraint):
            self.pending_constraint_count += 1
        self._cached_hash = None
        return cast("VMState", self)

    def record_branch(self, condition: z3.BoolRef, taken: bool, pc: int) -> VMState:
        """Append a branch-trace record without adding a path constraint."""
        record = BranchRecord(pc=pc, condition=condition, taken=taken)
        self.branch_trace = self.branch_trace.append(record)
        return cast("VMState", self)

    def mark_visited(self) -> bool:
        """Record the current ``pc`` in the path's visitation log.

        This method records a repeated program counter; exploration policy
        remains responsible for interpreting revisits as loops or bounds.

        Returns:
            ``True`` if the current ``pc`` was already present in
            ``visited_pcs``.
        """
        if self.pc in self.visited_pcs:
            return True
        self.visited_pcs.add(self.pc)
        self._cached_hash = None
        return False

    def enter_block(self, block: BlockInfo) -> VMState:
        """Push *block* onto the block stack.  Returns ``self``."""
        self.block_stack.append(block)
        self._cached_hash = None
        return cast("VMState", self)

    def exit_block(self) -> BlockInfo | None:
        """Pop the innermost block from the block stack.

        Returns the popped ``BlockInfo``, or ``None`` if the stack is empty.
        """
        if self.block_stack:
            block = self.block_stack.pop()
            self._cached_hash = None
            return block
        return None

    def push_call(self, frame: CallFrame) -> VMState:
        """Push *frame* onto the call stack.  Returns ``self``."""
        self.call_stack.append(frame)
        self._cached_hash = None
        return cast("VMState", self)

    def pop_call(self) -> CallFrame | None:
        """Pop the top call frame.

        Returns the popped ``CallFrame``, or ``None`` if the stack is empty.
        """
        if self.call_stack:
            frame = self.call_stack.pop()
            self._cached_hash = None
            return frame
        return None

    def get_local(self, name: str) -> StackValue | UnboundType:
        """Get a local variable, or UNBOUND if not found or cleared."""
        if name in self.local_vars:
            return self.local_vars[name]
        return UNBOUND

    def get_global(self, name: str) -> StackValue | None:
        """Get a global variable, or None if not found."""
        return self.global_vars.get(name)

    @property
    def locals(self) -> CowDict[str, StackValue]:
        """Alias for local_vars (used by some callers)."""
        return self.local_vars

    def current_block(self) -> BlockInfo | None:
        """Get the current control flow block."""
        return self.block_stack[-1] if self.block_stack else None

    def call_depth(self) -> int:
        """Get the current call stack depth."""
        return len(self.call_stack)

    def copy_constraints(self) -> list[z3.BoolRef]:
        """Get a copy of the current path constraints."""
        return self.path_constraints.to_list()

    def constraint_hash(self) -> int:
        """Return the persistent constraint chain's structural hash."""
        return self.path_constraints.hash_value()

    def hash_value(self) -> int:
        """Return a cached structural summary used for state deduplication.

        Notes:
            The summary covers selected stacks, stores, constraints,
            exceptions, detector-deferment sites, and loop bookkeeping. It is
            not a semantic-equivalence or path-feasibility proof.
        """
        if self._cached_hash is not None:
            return self._cached_hash

        h = self.pc * 2654435761
        h ^= self.constraint_hash() * 999999937

        for frame in self.call_stack:
            h = (h * 1000003) ^ frame.hash_value()

        for frame in self.contract_frames:
            h = (h * 1000003) ^ hash(repr(frame))

        for block in self.block_stack:
            h = (h * 1000003) ^ block.hash_value()

        for deferred in self.deferred_detector_issues:
            h = (h * 1000003) ^ hash(deferred.site_key)

        if self.active_exception is not None:
            h = (h * 1000003) ^ hash(repr(self.active_exception))
        if self.pending_reraise_exception is not None:
            h = (h * 1000003) ^ hash(repr(self.pending_reraise_exception))

        h ^= self.local_vars.hash_value() * 31
        h ^= self.global_vars.hash_value() * 1000003
        h ^= self.memory.hash_value() * 82520
        h ^= self.visited_pcs.hash_value() * 12345
        h ^= self.loop_iterations.hash_value() * 131
        h ^= self.loop_counters.hash_value() * 137
        h ^= self.freed_vars.hash_value() * 139
        h ^= self.prev_loop_states.hash_value() * 149
        for event in self.write_events:
            h = (h * 1000003) ^ hash(event)

        for v in self.stack:
            value_hash = structural_hash_or_none(v)
            if value_hash is None:
                if logger.state.debug_enabled:
                    logger.debug("Unhashable VM stack value while hashing state", exc_info=True)
                value_hash = 0
            h = (h * 31) ^ value_hash

        res = h & 0xFFFFFFFFFFFFFFFF
        self._cached_hash = res
        return res


__all__ = ["VMStateMutationMixin"]
