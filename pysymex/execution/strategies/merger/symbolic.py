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

"""Construct merged ``VMState`` objects via symbolic ``conditional_merge`` hooks.

Builds disjunctive constraints over locals/globals when policy allows joining
symbolic carriers at control-flow merges.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.typing import StackValue
from pysymex.core.memory.cow.collections import CowDict
from pysymex.execution.strategies.merger.helpers import (
    as_string_object_mapping,
    is_any_symbolic,
    is_conditional_mergeable,
    is_stack_value,
)
from pysymex.execution.strategies.merger.types import StateMergerMixinContract

if TYPE_CHECKING:
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState


class StateMergerSymbolicMixin(StateMergerMixinContract):
    """Perform symbolic merges of compatible states at join points."""

    def _merge_states_symbolically(self, state1: VMState, state2: VMState) -> VMState | None:
        """Merge states using strict Phi-nodes without Implies AST bloat."""

        condition = z3.Bool(f"phi_merge_p{state1.path_id}_p{state2.path_id}")
        if tuple(map(repr, state1.contract_frames)) != tuple(map(repr, state2.contract_frames)):
            return None

        def _merge_pair(
            left: StackValue,
            right: StackValue,
            merge_condition: z3.BoolRef,
        ) -> StackValue | None:
            from pysymex.core.types.scalars.values import SymbolicValue

            from pysymex.core.types.containers.dicts import SymbolicDict
            from pysymex.core.types.containers.sequences import SymbolicIterator
            from pysymex.core.types.containers.lists import SymbolicList
            from pysymex.core.types.containers.objects import SymbolicObject
            from pysymex.core.types.scalars.strings import SymbolicString

            if isinstance(left, SymbolicIterator) or isinstance(right, SymbolicIterator):
                return None

            _CONTAINER_TYPES = (SymbolicList, SymbolicDict, SymbolicString, SymbolicObject)
            left_is_container = isinstance(left, _CONTAINER_TYPES)
            right_is_container = isinstance(right, _CONTAINER_TYPES)
            if left_is_container != right_is_container:
                return None
            if left_is_container and right_is_container and type(left) is not type(right):
                return None

            left_symbolic: object = (
                left if is_any_symbolic(left) else SymbolicValue.from_const(left)
            )
            right_symbolic: object = (
                right if is_any_symbolic(right) else SymbolicValue.from_const(right)
            )
            try:
                if not is_conditional_mergeable(left_symbolic):
                    return None
                merged_obj = left_symbolic.conditional_merge(right_symbolic, merge_condition)
                if not is_stack_value(merged_obj):
                    return None
                return merged_obj
            except TypeError:
                return None

        merged = state1.fork()

        merged.path_constraints = state1.path_constraints

        for name in state1.local_vars:
            val1 = state1.local_vars[name]
            val2 = state2.local_vars[name]
            if self.values_structurally_equal(val1, val2):
                merged.local_vars[name] = val1
                continue

            merged_value = _merge_pair(val1, val2, condition)
            if merged_value is None:
                return None
            merged.local_vars[name] = merged_value

        all_global_keys = set(state1.global_vars.keys()) | set(state2.global_vars.keys())
        for name in all_global_keys:
            val1 = state1.global_vars.get(name)
            val2 = state2.global_vars.get(name)
            if val1 is not None and val2 is not None:
                if self.values_structurally_equal(val1, val2):
                    merged.global_vars[name] = val1
                    continue
                merged_value = _merge_pair(val1, val2, condition)
                if merged_value is None:
                    return None
                merged.global_vars[name] = merged_value
            elif val1 is not None:
                merged.global_vars[name] = val1
            elif val2 is not None:
                merged.global_vars[name] = val2

        merged_stack: list[StackValue] = []
        for val1, val2 in zip(state1.stack, state2.stack):
            if self.values_structurally_equal(val1, val2):
                merged_stack.append(val1)
                continue
            merged_value = _merge_pair(val1, val2, condition)
            if merged_value is None:
                return None
            merged_stack.append(merged_value)
        merged.stack = merged_stack

        if len(state1.call_stack) == len(state2.call_stack):
            from pysymex.core.state.types import wrap_cow_dict

            merged_call_stack: list[CallFrame] = []
            for f1, f2 in zip(state1.call_stack, state2.call_stack, strict=False):
                if f1.function_name != f2.function_name or f1.return_pc != f2.return_pc:
                    return None

                frame_locals_seed: dict[str, StackValue] = {}
                merged_frame_locals = wrap_cow_dict(frame_locals_seed)
                all_keys = set(f1.local_vars.keys()) | set(f2.local_vars.keys())
                for k in all_keys:
                    v1 = f1.local_vars.get(k)
                    v2 = f2.local_vars.get(k)
                    if v1 is not None and v2 is not None:
                        if self.values_structurally_equal(v1, v2):
                            merged_frame_locals[k] = v1
                            continue
                        mv = _merge_pair(v1, v2, condition)
                        if mv is None:
                            return None
                        merged_frame_locals[k] = mv
                    else:
                        merged_frame_locals[k] = v1 if v1 is not None else v2

                from dataclasses import replace

                mf = replace(f1, local_vars=merged_frame_locals)
                merged_call_stack.append(mf)
            merged.call_stack = merged_call_stack
        elif state1.call_stack or state2.call_stack:
            return None

        all_addrs = set(state1.memory.keys()) | set(state2.memory.keys())
        merged.memory = CowDict[int, StackValue]()
        for addr in all_addrs:
            cell1 = state1.memory.get(addr)
            cell2 = state2.memory.get(addr)
            dict1 = as_string_object_mapping(cell1)
            dict2 = as_string_object_mapping(cell2)
            if dict1 is None or dict2 is None:
                if cell1 is not None and cell2 is not None:
                    if self.values_structurally_equal(cell1, cell2):
                        merged.memory[addr] = cell1
                        continue
                    merged_cell = _merge_pair(cell1, cell2, condition)
                    if merged_cell is None:
                        return None
                    merged.memory[addr] = merged_cell
                elif cell1 is not None:
                    merged.memory[addr] = cell1
                elif cell2 is not None:
                    merged.memory[addr] = cell2
                continue

            merged_dict: dict[str, StackValue] = {}
            all_attrs = set(dict1.keys()) | set(dict2.keys())
            for attr in all_attrs:
                v1 = dict1.get(attr)
                v2 = dict2.get(attr)
                if v1 is not None and v2 is not None:
                    if v1 is v2:
                        merged_dict[attr] = v1
                        continue
                    if self.values_structurally_equal(v1, v2):
                        merged_dict[attr] = v1
                        continue
                    merged_val = _merge_pair(v1, v2, condition)
                    if merged_val is None:
                        return None
                    merged_dict[attr] = merged_val
                elif v1 is not None:
                    merged_dict[attr] = v1
                elif v2 is not None:
                    merged_dict[attr] = v2
            merged.memory[addr] = dict(merged_dict)
        return merged
