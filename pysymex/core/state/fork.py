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

"""Copy-on-write branching operations for execution-path VM state."""

from __future__ import annotations

import itertools
from typing import TYPE_CHECKING, cast

from pysymex.core.state._mixin_types import VMStateMixinAttributes
from pysymex.core.state.types import CallFrame, copy_summary_builder
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


_path_id_counter = itertools.count()
logger = get_logger(__name__)


class VMStateForkMixin(VMStateMixinAttributes):
    """Create child execution states while preserving path-local isolation.

    Copy-on-write stores and persistent constraint/branch chain heads are
    retained in the child until replaced by later mutation. List-backed
    path-local containers are copied, and call-frame summary builders are
    cloned when present.

    Limitations:
        Some referenced values, instructions, exception objects, registries,
        and resource-count metadata remain shared or copied according to their
        existing representation; this mixin does not establish deep isolation
        for arbitrary referenced objects.
    """

    def _replace(self, **changes: object) -> VMState:
        """Create a CoW **fork** with specific fields altered.

        Use this when you need a *new* independent state (e.g. branching).
        For single-path mutation, use the fluent helpers instead.
        """
        child = self.fork()
        for attr, value in changes.items():
            setattr(child, attr, value)
        return child

    def fork(self) -> VMState:
        """Create a child state for a new symbolic-exploration path.

        Side Effects:
            Allocates a new path identifier and may clone mutable call-frame
            summary builders.

        Returns:
            A child state with copy-on-write stores, copied list-backed path
            containers, and retained persistent constraint/branch histories.

        Raises:
            VMStateError: If a present call-frame summary builder cannot be
                cloned through its required clone contract.

        Limitations:
            Forking does not deep-copy every value reachable from state fields.
        """
        new_path_id = next(_path_id_counter)

        if not self.call_stack:
            new_call_stack: list[CallFrame] = []
        else:
            needs_deep_copy = any(f.summary_builder is not None for f in self.call_stack)

            if not needs_deep_copy:
                new_call_stack = list(self.call_stack)
            else:
                new_call_stack = [
                    CallFrame(
                        function_name=f.function_name,
                        return_pc=f.return_pc,
                        local_vars=f.local_vars.cow_fork(),
                        stack_depth=f.stack_depth,
                        caller_stack=f.caller_stack,
                        caller_instructions=f.caller_instructions,
                        summary_builder=(
                            copy_summary_builder(f.summary_builder)
                            if f.summary_builder is not None
                            else None
                        ),
                        is_init_call=f.is_init_call,
                        init_instance=f.init_instance,
                        protocol_method=f.protocol_method,
                        protocol_retained_operand=f.protocol_retained_operand,
                        protocol_fallbacks=f.protocol_fallbacks,
                        argument_aliases=f.argument_aliases,
                        caller_offset=f.caller_offset,
                    )
                    for f in self.call_stack
                ]

        child = type(self).__new__(type(self))
        child.stack = list(self.stack) if self.stack else []
        child.local_vars = self.local_vars.cow_fork()
        child.global_vars = self.global_vars.cow_fork()
        child.path_constraints = self.path_constraints
        child.pc = self.pc
        child.block_stack = list(self.block_stack) if self.block_stack else []
        child.call_stack = new_call_stack
        child.contract_frames = list(self.contract_frames) if self.contract_frames else []
        child.visited_pcs = self.visited_pcs.cow_fork()
        child.memory = self.memory.cow_fork()
        child.path_id = new_path_id
        child.depth = self.depth
        child.current_instructions = self.current_instructions
        child.active_exception = self.active_exception
        child.pending_reraise_exception = self.pending_reraise_exception
        child.deferred_detector_issues = (
            list(self.deferred_detector_issues) if self.deferred_detector_issues else []
        )
        child.pending_constraint_count = self.pending_constraint_count
        child.last_inconclusive_feasibility_len = self.last_inconclusive_feasibility_len
        child.loop_iterations = self.loop_iterations.cow_fork()
        child.loop_counters = self.loop_counters.cow_fork()
        child.freed_vars = self.freed_vars.cow_fork()
        child.prev_loop_states = self.prev_loop_states.cow_fork()
        child.branch_trace = self.branch_trace
        child.open_resources = self.open_resources
        child.write_events = list(self.write_events) if self.write_events else []
        child._cached_hash = self._cached_hash
        child.pending_kw_names = self.pending_kw_names
        child.current_coro_id = self.current_coro_id
        child.awaitable_results = dict(self.awaitable_results) if self.awaitable_results else {}

        if logger.state.trace_enabled:
            logger.trace(
                "forked state parent_path_id=%d child_path_id=%d pc=%d depth=%d constraints=%d",
                self.path_id,
                child.path_id,
                child.pc,
                child.depth,
                len(child.path_constraints),
            )
        return cast("VMState", child)

    def copy(self) -> VMState:
        """Return a new-path fork of this state."""
        return self.fork()

    def replace(self, **changes: object) -> VMState:
        """Fork this state and apply attribute changes to the child.

        Usage::

            new_state = state.replace(pc=target_pc, depth=state.depth + 1)

        Returns:
            A new VMState (fork) with the specified attributes overwritten.

        Notes:
            Attribute names and replacement values are assigned directly after
            forking; this helper does not validate semantic consistency.
        """
        return self._replace(**changes)

    def __repr__(self) -> str:
        """Return a diagnostic summary of this path-local VM state."""
        return (
            f"VMState(path={self.path_id}, pc={self.pc}, "
            f"stack_depth={len(self.stack)}, "
            f"constraints={len(self.path_constraints)})"
        )


__all__ = ["VMStateForkMixin"]
