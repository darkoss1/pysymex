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

"""Structural equality checks between ``VMState`` payloads.

Compares stacks, locals, globals, and path constraints before symbolic merge
attempts proceed.
"""

from __future__ import annotations

from pysymex.logger import get_logger
from collections.abc import Mapping
from typing import TYPE_CHECKING

import z3

from pysymex.execution.strategies.merger.helpers import (
    HashableValue,
    as_string_object_mapping,
)
from pysymex.execution.strategies.merger.types import StateMergerMixinContract

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.core.types.scalars.values import SymbolicValue

logger = get_logger(__name__)


class StateMergerEqualityMixin(StateMergerMixinContract):
    """Determine whether two states are structurally compatible for merging."""

    def _state_payload_equal(self, state1: VMState, state2: VMState) -> bool:
        """Check exact equality of non-constraint state payload."""

        if state1.visited_pcs.hash_value() != state2.visited_pcs.hash_value():
            return False
        if state1.local_vars.hash_value() != state2.local_vars.hash_value():
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
            frame1_locals = as_string_object_mapping(frame1.local_vars)
            frame2_locals = as_string_object_mapping(frame2.local_vars)
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

        state1_locals = as_string_object_mapping(state1.local_vars)
        state2_locals = as_string_object_mapping(state2.local_vars)
        if state1_locals is None or state2_locals is None:
            return False
        if not self.mapping_equal(state1_locals, state2_locals):
            return False
        state1_globals = as_string_object_mapping(state1.global_vars)
        state2_globals = as_string_object_mapping(state2.global_vars)
        if state1_globals is None or state2_globals is None:
            return False
        if not self.mapping_equal(state1_globals, state2_globals):
            return False

        for addr in state1.memory.keys():
            if addr not in state2.memory:
                return False
            cell1 = state1.memory.get(addr)
            cell2 = state2.memory.get(addr)
            dict1 = as_string_object_mapping(cell1)
            dict2 = as_string_object_mapping(cell2)
            if dict1 is None or dict2 is None:
                if not self.values_structurally_equal(cell1, cell2):
                    return False
                continue
            if not self.mapping_equal(dict1, dict2):
                return False
        return True

    def _frame_caller_stack_equal(
        self, left: tuple[object, ...] | None, right: tuple[object, ...] | None
    ) -> bool:
        """Compare caller stack snapshots retained in suspended call frames."""
        if left is None or right is None:
            return left is right
        return len(left) == len(right) and all(
            self.values_structurally_equal(l_value, r_value)
            for l_value, r_value in zip(left, right, strict=False)
        )

    def mapping_hash_mismatch(
        self, left: Mapping[str, object], right: Mapping[str, object]
    ) -> bool:
        """Fast-fail if both mappings expose content hashes and they differ."""
        left_hash_getter = getattr(left, "hash_value", None)
        right_hash_getter = getattr(right, "hash_value", None)
        if callable(left_hash_getter) and callable(right_hash_getter):
            left_hash = left_hash_getter()
            right_hash = right_hash_getter()
            if isinstance(left_hash, int) and isinstance(right_hash, int):
                return left_hash != right_hash
        return False

    def mapping_equal(self, left: Mapping[str, object], right: Mapping[str, object]) -> bool:
        """Compare string-keyed mappings using structural value equality."""
        if left is right:
            return True
        if len(left) != len(right):
            return False
        if self.mapping_hash_mismatch(left, right):
            return False
        for key, value in left.items():
            if key not in right:
                return False
            if not self.values_structurally_equal(value, right[key]):
                return False
        return True

    def _can_merge_symbolically(self, state1: VMState, state2: VMState) -> bool:
        """Check if states are compatible for symbolic merging.

        Requirements:
        1. Same PC (obviously)
        2. Same stack depth (structure of execution must match)
        3. Same call stack depth
        4. Same set of local variables (roughly)
        5. Same block stack structure
        6. Prevent path explosion: Path constraints must be structurally identical.
        """
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

        for c1, c2 in zip(cons1, cons2):
            if not self.constraints_equal(c1, c2):
                return False

        return True

    def _symbolic_values_equal(self, left: SymbolicValue, right: SymbolicValue) -> bool:
        """Check structural equality of SymbolicValue instances."""
        if bool(getattr(left, "_h_active", False)) != bool(getattr(right, "_h_active", False)):
            return False
        if getattr(left, "_modeled_object", None) is not getattr(right, "_modeled_object", None):
            return False
        if left.affinity_type != right.affinity_type:
            return False
        if left.min_val != right.min_val or left.max_val != right.max_val:
            return False

        if not z3.eq(left.z3_int, right.z3_int):
            return False
        if not z3.eq(left.is_int, right.is_int):
            return False
        if not z3.eq(left.z3_bool, right.z3_bool):
            return False
        if not z3.eq(left.is_bool, right.is_bool):
            return False
        if not z3.eq(left.z3_float, right.z3_float):
            return False
        if not z3.eq(left.is_float, right.is_float):
            return False
        if not z3.eq(left.z3_str, right.z3_str):
            return False
        if not z3.eq(left.is_str, right.is_str):
            return False
        if not z3.eq(left.z3_addr, right.z3_addr):
            return False
        if not z3.eq(left.is_obj, right.is_obj):
            return False
        if not z3.eq(left.is_path, right.is_path):
            return False
        if not z3.eq(left.is_none, right.is_none):
            return False
        if not z3.eq(left.is_list, right.is_list):
            return False
        if not z3.eq(left.is_dict, right.is_dict):
            return False
        if left.z3_array is None:
            if right.z3_array is not None:
                return False
        else:
            if right.z3_array is None or not z3.eq(left.z3_array, right.z3_array):
                return False
        return True

    def values_structurally_equal(self, left: object, right: object) -> bool:
        """Best-effort structural equality without trusting hash collisions."""
        if left is right:
            return True
        if isinstance(left, z3.ExprRef):
            return isinstance(right, z3.ExprRef) and z3.eq(left, right)

        from pysymex.core.types.scalars.values import SymbolicValue

        if isinstance(left, SymbolicValue):
            if not isinstance(right, SymbolicValue):
                return False
            if left.hash_value() != right.hash_value():
                return False
            return self._symbolic_values_equal(left, right)

        if isinstance(left, HashableValue) and isinstance(right, HashableValue):
            if left.hash_value() != right.hash_value():
                return False

        try:
            eq_result = left == right
        except (AttributeError, TypeError, RuntimeError) as exc:
            logger.debug("Symbolic value equality check failed: %s", exc)
            return False
        return eq_result

    def constraints_equal(self, c1: z3.BoolRef, c2: z3.BoolRef) -> bool:
        """Check if two constraints are equivalent."""
        if c1 is c2 or c1.hash() == c2.hash():
            return True
        try:
            return z3.eq(c1, c2)
        except z3.Z3Exception:
            return str(c1) == str(c2)
