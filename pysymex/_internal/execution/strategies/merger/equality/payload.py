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

"""State payload compatibility checks before symbolic merging."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.strategies.merger.merge_guards import MergeGuards
from pysymex._internal.execution.strategies.merger.types import StateMergerMixinContract

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


class StatePayloadEqualityMixin(StateMergerMixinContract):
    """Determine whether two states are structurally compatible for merging."""

    def _state_payload_equal(
        self,
        state1: VMState,
        state2: VMState,
        *,
        ignore_visited_pcs: bool = False,
        ignore_local_vars: bool = False,
    ) -> bool:
        """Check exact equality of non-constraint state payload."""
        if (
            not ignore_visited_pcs
            and state1.visited_pcs.hash_value() != state2.visited_pcs.hash_value()
        ):
            return False
        if (
            not ignore_local_vars
            and state1.local_vars.hash_value() != state2.local_vars.hash_value()
        ):
            return False
        if state1.global_vars.hash_value() != state2.global_vars.hash_value():
            return False
        if len(state1.memory) != len(state2.memory):
            return False
        if state1.memory.hash_value() != state2.memory.hash_value():
            return False

        if len(state1.stack) != len(state2.stack):
            return False
        for left, right in zip(state1.stack, state2.stack, strict=False):
            if not self.values_structurally_equal(left, right):
                return False

        if len(state1.call_stack) != len(state2.call_stack):
            return False
        for frame1, frame2 in zip(state1.call_stack, state2.call_stack, strict=False):
            if frame1.function_name != frame2.function_name or frame1.return_pc != frame2.return_pc:
                return False
            if not self._frame_caller_stack_equal(frame1.caller_stack, frame2.caller_stack):
                return False
            frame1_locals = MergeGuards.as_mapping(frame1.local_vars)
            frame2_locals = MergeGuards.as_mapping(frame2.local_vars)
            if frame1_locals is None or frame2_locals is None:
                return False
            if self.mapping_hash_mismatch(frame1_locals, frame2_locals):
                return False
            if not self.mapping_equal(frame1_locals, frame2_locals):
                return False

        if len(state1.block_stack) != len(state2.block_stack):
            return False
        for block1, block2 in zip(state1.block_stack, state2.block_stack, strict=False):
            if block1.block_type != block2.block_type or block1.handler_pc != block2.handler_pc:
                return False

        if not ignore_local_vars:
            state1_locals = MergeGuards.as_mapping(state1.local_vars)
            state2_locals = MergeGuards.as_mapping(state2.local_vars)
            if state1_locals is None or state2_locals is None:
                return False
            if not self.mapping_equal(state1_locals, state2_locals):
                return False
        state1_globals = MergeGuards.as_mapping(state1.global_vars)
        state2_globals = MergeGuards.as_mapping(state2.global_vars)
        if state1_globals is None or state2_globals is None:
            return False
        if not self.mapping_equal(state1_globals, state2_globals):
            return False

        for addr in state1.memory:
            if addr not in state2.memory:
                return False
            cell1 = state1.memory.get(addr)
            cell2 = state2.memory.get(addr)
            dict1 = MergeGuards.as_mapping(cell1)
            dict2 = MergeGuards.as_mapping(cell2)
            if dict1 is None or dict2 is None:
                if not self.values_structurally_equal(cell1, cell2):
                    return False
                continue
            if not self.mapping_equal(dict1, dict2):
                return False
        return True

    def _can_merge_symbolically(self, state1: VMState, state2: VMState) -> bool:
        """Check if states are compatible for symbolic merging."""
        if len(state1.stack) != len(state2.stack):
            return False
        if len(state1.call_stack) != len(state2.call_stack):
            return False
        for frame1, frame2 in zip(state1.call_stack, state2.call_stack, strict=False):
            if frame1.function_name != frame2.function_name or frame1.return_pc != frame2.return_pc:
                return False
            if not self._frame_caller_stack_equal(frame1.caller_stack, frame2.caller_stack):
                return False
        keys1 = set(state1.local_vars.keys())
        keys2 = set(state2.local_vars.keys())
        if keys1 != keys2:
            return False
        if len(state1.block_stack) != len(state2.block_stack):
            return False
        for b1, b2 in zip(state1.block_stack, state2.block_stack, strict=False):
            if b1.block_type != b2.block_type or b1.handler_pc != b2.handler_pc:
                return False

        if state1.visited_pcs.hash_value() != state2.visited_pcs.hash_value():
            return False

        cons1 = state1.path_constraints.to_list()
        cons2 = state2.path_constraints.to_list()
        if len(cons1) != len(cons2):
            return False

        return all(self.constraints_equal(c1, c2) for c1, c2 in zip(cons1, cons2, strict=False))
