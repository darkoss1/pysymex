# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
State Merging for Symbolic Execution.

This module provides smart state merging at control-flow join points
to reduce path explosion while maintaining analysis soundness.

Features:
- Join-point detection via CFG analysis
- Abstract domain-based value merging
- Configurable merge policies
- Constraint subsumption for redundant path elimination
"""

from __future__ import annotations

import types
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

import z3

from pysymex._typing import StackValue
from pysymex.core.memory.cow import ConstraintChain, CowDict

if TYPE_CHECKING:
    import dis

    from pysymex.core.state import VMState
    from pysymex.core.types.scalars import SymbolicValue


class MergePolicy(Enum):
    """Merge aggressiveness policies for state merging."""

    CONSERVATIVE = auto()
    MODERATE = auto()
    AGGRESSIVE = auto()


@dataclass
class MergeStatistics:
    """Accumulator for state-merging statistics.

    Attributes:
        states_before_merge: Total states seen.
        states_after_merge: States remaining after merging.
        merge_operations: Number of successful merges.
        subsumption_hits: Number of subsumption-based prunings.
    """

    states_before_merge: int = 0
    states_after_merge: int = 0
    merge_operations: int = 0
    subsumption_hits: int = 0

    @property
    def reduction_ratio(self) -> float:
        """Property returning the reduction_ratio."""
        if self.states_before_merge == 0:
            return 0.0
        return 1.0 - (self.states_after_merge / self.states_before_merge)


@dataclass
class AbstractVarInfo:
    """Abstract information about a variable at a merge point.

    Attributes:
        interval_lo: Lower bound of the integer interval.
        interval_hi: Upper bound of the integer interval.
        may_be_none: Whether the variable may be ``None``.
        must_be_type: Inferred concrete type, if known.
        is_tainted: Whether the variable carries taint.
    """

    interval_lo: int | None = None
    interval_hi: int | None = None
    may_be_none: bool = False
    must_be_type: str | None = None
    is_tainted: bool = False


class StateMerger:
    """Merges equivalent states at control-flow join points using Symbolic Merging.

    Instead of approximating values (Abstract Interpretation), this merger constructs
    precise Z3 formulas to represent the union of two path states:
    merged_val = If(branch_condition, val_true_path, val_false_path)
    """

    def __init__(
        self,
        policy: MergePolicy = MergePolicy.MODERATE,
        max_constraints_for_merge: int = 50,
        similarity_threshold: float = 0.7,
    ) -> None:
        self.policy = policy
        self.max_constraints_for_merge = max_constraints_for_merge
        self.similarity_threshold = similarity_threshold
        self.stats = MergeStatistics()
        self._join_points: set[int] = set()
        self._pending_states: dict[int, dict[int, list[VMState]]] = {}

    def set_join_points(self, join_points: set[int]) -> None:
        """Set the CFG join points for merge consideration."""
        self._join_points = join_points

    def detect_join_points(
        self, instructions: list[dis.Instruction], code: types.CodeType | None = None
    ) -> set[int]:
        """Detect join points using bytecode predecessor counts.

        A join point is any instruction offset reached by more than one
        predecessor edge in the control-flow graph.
        """
        _ = code

        if not instructions:
            self._join_points = set()
            return self._join_points

        import dis as _dis

        predecessor_counts: dict[int, int] = {}

        for idx, instr in enumerate(instructions):
            successors: set[int] = set()
            opname = instr.opname

            # Explicit jump target edge.
            if instr.opcode in _dis.hasjabs or instr.opcode in _dis.hasjrel:
                jump_target = instr.argval
                if isinstance(jump_target, int):
                    successors.add(jump_target)

            has_fallthrough = True
            if opname.startswith("RETURN") or opname in {"RAISE_VARARGS", "RERAISE"}:
                has_fallthrough = False
            if opname.startswith("JUMP") and "IF" not in opname and opname not in {
                "JUMP_IF_TRUE_OR_POP",
                "JUMP_IF_FALSE_OR_POP",
            }:
                has_fallthrough = False

            if has_fallthrough and idx + 1 < len(instructions):
                successors.add(instructions[idx + 1].offset)

            for succ in successors:
                predecessor_counts[succ] = predecessor_counts.get(succ, 0) + 1

        self._join_points = {offset for offset, count in predecessor_counts.items() if count > 1}
        return self._join_points

    def is_join_point(self, pc: int) -> bool:
        """Check if a program counter is at a join point."""
        return pc in self._join_points

    def should_merge(self, state: VMState) -> bool:
        """Determine if the state should be considered for merging."""
        if not self.is_join_point(state.pc):
            return False
        if len(state.path_constraints) > self.max_constraints_for_merge:
            return False
        return True

    def _structural_hash(self, state: VMState) -> int:
        """Compute a structural hash to fast-fail basic structure differences."""
        return hash(
            (
                len(state.stack),
                len(state.call_stack),
                frozenset(state.local_vars.keys()),
                tuple((b.block_type, b.handler_pc) for b in state.block_stack),
            )
        )

    def add_state_for_merge(self, state: VMState) -> VMState | None:
        """Add a state for potential merging. Returns merged state or None."""
        pc = state.pc
        if pc not in self._pending_states:
            self._pending_states[pc] = {}

        target_hash = self._structural_hash(state)
        if target_hash not in self._pending_states[pc]:
            self._pending_states[pc][target_hash] = []

        pending = self._pending_states[pc][target_hash]
        self.stats.states_before_merge += 1

        i = 0
        while i < len(pending):
            existing = pending[i]

            if self._state_payload_equal(existing, state):
                if self._constraints_subsume(existing, state):
                    self.stats.subsumption_hits += 1
                    return None
                if self._constraints_subsume(state, existing):
                    pending.pop(i)
                    self.stats.states_after_merge = max(0, self.stats.states_after_merge - 1)
                    self.stats.subsumption_hits += 1
                    continue
            i += 1

        for i, existing in enumerate(pending):
            if self._can_merge_symbolically(state, existing):
                merged = self._merge_states_symbolically(state, existing)
                if merged:
                    pending.pop(i)
                    pending.append(merged)
                    self.stats.merge_operations += 1
                    return merged
        pending.append(state)
        self.stats.states_after_merge += 1
        return state

    def _constraints_subsume(self, subsumer: VMState, subsumed: VMState) -> bool:
        """Return True when ``subsumer`` safely covers ``subsumed`` exactly.
        Assumes payload equality has already been verified.
        """
        subsumer_constraints = subsumer.path_constraints.to_list()
        subsumed_constraints = subsumed.path_constraints.to_list()
        if len(subsumer_constraints) > len(subsumed_constraints):
            return False

        for left, right in zip(subsumer_constraints, subsumed_constraints, strict=False):
            if not self._constraints_equal(left, right):
                return False
        return True

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
            if not self._values_structurally_equal(left, right):
                return False

        if len(state1.call_stack) != len(state2.call_stack):
            return False
        for frame1, frame2 in zip(state1.call_stack, state2.call_stack, strict=False):
            if frame1.function_name != frame2.function_name or frame1.return_pc != frame2.return_pc:
                return False
            if self._mapping_hash_mismatch(
                cast("Mapping[str, object]", frame1.local_vars),
                cast("Mapping[str, object]", frame2.local_vars),
            ):
                return False
            if not self._mapping_equal(
                cast("Mapping[str, object]", frame1.local_vars),
                cast("Mapping[str, object]", frame2.local_vars),
            ):
                return False

        if len(state1.block_stack) != len(state2.block_stack):
            return False
        for block1, block2 in zip(state1.block_stack, state2.block_stack, strict=False):
            if block1.block_type != block2.block_type or block1.handler_pc != block2.handler_pc:
                return False

        if not self._mapping_equal(
            cast("Mapping[str, object]", state1.local_vars),
            cast("Mapping[str, object]", state2.local_vars),
        ):
            return False
        if not self._mapping_equal(
            cast("Mapping[str, object]", state1.global_vars),
            cast("Mapping[str, object]", state2.global_vars),
        ):
            return False

        for addr in state1.memory.keys():
            if addr not in state2.memory:
                return False
            cell1 = state1.memory.get(addr)
            cell2 = state2.memory.get(addr)
            dict1 = _as_string_object_mapping(cell1)
            dict2 = _as_string_object_mapping(cell2)
            if dict1 is None or dict2 is None:
                if not self._values_structurally_equal(cell1, cell2):
                    return False
                continue
            if not self._mapping_equal(dict1, dict2):
                return False
        return True

    def _mapping_hash_mismatch(
        self, left: Mapping[str, object], right: Mapping[str, object]
    ) -> bool:
        """Fast-fail if both mappings expose content hashes and they differ."""
        left_hash_getter = getattr(left, "hash_value", None)
        right_hash_getter = getattr(right, "hash_value", None)
        if callable(left_hash_getter) and callable(right_hash_getter):
            return cast("int", left_hash_getter()) != cast("int", right_hash_getter())
        return False

    def _mapping_equal(self, left: Mapping[str, object], right: Mapping[str, object]) -> bool:
        """Compare string-keyed mappings using structural value equality."""
        if left is right:
            return True
        if len(left) != len(right):
            return False
        if self._mapping_hash_mismatch(left, right):
            return False
        for key, value in left.items():
            if key not in right:
                return False
            if not self._values_structurally_equal(value, right[key]):
                return False
        return True

    def _can_merge_symbolically(self, state1: VMState, state2: VMState) -> bool:
        """Check if states are compatible for symbolic merging.

        Requirements:
        1. Same PC (obviously)
        2. Same stack depth (structure of execution must match)
        3. Same call stack depth
        4. Same set of local variables (roughly)
        5. Same block stack structure (block_type + handler_pc per entry)
        """
        if len(state1.stack) != len(state2.stack):
            return False
        if len(state1.call_stack) != len(state2.call_stack):
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
        return True

    def _extract_branch_condition(
        self, state1: VMState, state2: VMState
    ) -> tuple[z3.BoolRef | None, int]:
        """Find the condition that distinguishes state1 from state2.
        Returns (condition, common_len).
        """
        cons1 = state1.path_constraints.to_list()
        cons2 = state2.path_constraints.to_list()
        common_len = 0
        min_len = min(len(cons1), len(cons2))
        while common_len < min_len:
            if not self._constraints_equal(cons1[common_len], cons2[common_len]):
                break
            common_len += 1

        if common_len >= len(cons1) or common_len >= len(cons2):
            return None, common_len

        c1 = cons1[common_len]
        c2 = cons2[common_len]

        s1 = z3.simplify(c1)
        s2 = z3.simplify(c2)

        if z3.eq(s1, z3.simplify(z3.Not(s2))):
            return s1, common_len
        if z3.eq(s2, z3.simplify(z3.Not(s1))):
            return s1, common_len

        return c1, common_len

    def _merge_states_symbolically(self, state1: VMState, state2: VMState) -> VMState | None:
        """Merge states by creating conditional symbolic values."""
        condition, common_len = self._extract_branch_condition(state1, state2)
        if condition is None:
            return None

        def _merge_pair(
            left: StackValue,
            right: StackValue,
            merge_condition: z3.BoolRef,
        ) -> StackValue | None:
            """Merge pair."""
            from pysymex.core.types.scalars import SymbolicValue

            from pysymex.core.types.containers import (
                SymbolicDict,
                SymbolicList,
                SymbolicObject,
                SymbolicString,
            )

            _CONTAINER_TYPES = (SymbolicList, SymbolicDict, SymbolicString, SymbolicObject)
            left_is_container = isinstance(left, _CONTAINER_TYPES)
            right_is_container = isinstance(right, _CONTAINER_TYPES)
            if left_is_container != right_is_container:
                return None
            if left_is_container and right_is_container and type(left) is not type(right):
                return None

            left_symbolic: object = (
                left if _is_any_symbolic(left) else SymbolicValue.from_const(left)
            )
            right_symbolic: object = (
                right if _is_any_symbolic(right) else SymbolicValue.from_const(right)
            )
            try:
                merged_obj = cast("_ConditionalMergeable", left_symbolic).conditional_merge(
                    right_symbolic,
                    merge_condition,
                )
                return cast("StackValue", merged_obj)
            except TypeError:
                return None

        merged = state1.fork()

        new_chain = ConstraintChain.empty()

        base_constraints = state1.path_constraints.to_list()
        common_cons = base_constraints[:common_len]
        for c in common_cons:
            new_chain = new_chain.append(c)

        extra1 = base_constraints[common_len:]
        extra2 = state2.path_constraints.to_list()[common_len:]

        for c in extra1:
            new_chain = new_chain.append(z3.Implies(condition, c))
        for c in extra2:
            new_chain = new_chain.append(z3.Implies(z3.Not(condition), c))

        merged.path_constraints = new_chain
        for name in state1.local_vars:
            val1 = state1.local_vars[name]
            val2 = state2.local_vars[name]
            merged_value = _merge_pair(val1, val2, condition)
            if merged_value is None:
                return None
            merged.local_vars[name] = merged_value
        all_global_keys = set(state1.global_vars.keys()) | set(state2.global_vars.keys())
        for name in all_global_keys:
            val1 = state1.global_vars.get(name)
            val2 = state2.global_vars.get(name)
            if val1 is not None and val2 is not None:
                merged_value = _merge_pair(val1, val2, condition)
                if merged_value is None:
                    return None
                merged.global_vars[name] = merged_value
            elif val1 is not None:
                merged.global_vars[name] = val1
            elif val2 is not None:
                merged.global_vars[name] = val2
        merged_stack: list[StackValue] = []
        for i in range(len(state1.stack)):
            val1 = state1.stack[i]
            val2 = state2.stack[i]
            merged_value = _merge_pair(val1, val2, condition)
            if merged_value is None:
                return None
            merged_stack.append(merged_value)
        merged.stack = merged_stack

        if len(state1.call_stack) == len(state2.call_stack):
            from pysymex.core.state import wrap_cow_dict

            merged_call_stack = []
            for f1, f2 in zip(state1.call_stack, state2.call_stack, strict=False):
                if f1.function_name != f2.function_name or f1.return_pc != f2.return_pc:
                    return None

                merged_frame_locals = wrap_cow_dict({})
                all_keys = set(f1.local_vars.keys()) | set(f2.local_vars.keys())
                for k in all_keys:
                    v1 = f1.local_vars.get(k)
                    v2 = f2.local_vars.get(k)
                    if v1 is not None and v2 is not None:
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
        merged.memory = CowDict()
        for addr in all_addrs:
            cell1 = state1.memory.get(addr)
            cell2 = state2.memory.get(addr)
            dict1 = _as_string_object_mapping(cell1)
            dict2 = _as_string_object_mapping(cell2)
            if dict1 is None or dict2 is None:
                if cell1 is not None and cell2 is not None:
                    merged_cell = _merge_pair(cell1, cell2, condition)
                    if merged_cell is None:
                        return None
                    merged.memory[addr] = merged_cell
                elif cell1 is not None:
                    merged.memory[addr] = cell1
                elif cell2 is not None:
                    merged.memory[addr] = cell2
                continue

            merged_dict: dict[str, object] = {}
            all_attrs = set(dict1.keys()) | set(dict2.keys())
            for attr in all_attrs:
                v1 = dict1.get(attr)
                v2 = dict2.get(attr)
                if v1 is not None and v2 is not None:
                    if v1 is v2:
                        merged_dict[attr] = v1
                        continue
                    if self._values_structurally_equal(v1, v2):
                        merged_dict[attr] = v1
                        continue
                    merged_val = _merge_pair(
                        cast("StackValue", v1), cast("StackValue", v2), condition
                    )
                    if merged_val is None:
                        return None
                    merged_dict[attr] = merged_val
                elif v1 is not None:
                    merged_dict[attr] = v1
                elif v2 is not None:
                    merged_dict[attr] = v2
            from pysymex.core.state import wrap_cow_dict

            merged.memory[addr] = wrap_cow_dict(merged_dict)
        return merged

    def _symbolic_values_equal(self, left: SymbolicValue, right: SymbolicValue) -> bool:
        """Check structural equality of SymbolicValue instances."""
        if left.taint_labels != right.taint_labels:
            return False
        if bool(getattr(left, "_h_active", False)) != bool(getattr(right, "_h_active", False)):
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

    def _values_structurally_equal(self, left: object, right: object) -> bool:
        """Best-effort structural equality without trusting hash collisions."""
        if left is right:
            return True
        if isinstance(left, z3.ExprRef):
            return isinstance(right, z3.ExprRef) and z3.eq(left, right)

        from pysymex.core.types.scalars import SymbolicValue

        if isinstance(left, SymbolicValue):
            if not isinstance(right, SymbolicValue):
                return False
            if left.hash_value() != right.hash_value():
                return False
            return self._symbolic_values_equal(left, right)

        if isinstance(left, _HashableValue) and isinstance(right, _HashableValue):
            if left.hash_value() != right.hash_value():
                return False

        try:
            eq_result = left == right
        except Exception:
            return False
        return eq_result

    def _constraints_equal(self, c1: z3.BoolRef, c2: z3.BoolRef) -> bool:
        """Check if two constraints are equivalent."""
        if c1 is c2 or c1.hash() == c2.hash():
            return True
        try:
            return z3.eq(c1, c2)
        except z3.Z3Exception:
            return str(c1) == str(c2)

    def get_pending_states(self, pc: int) -> list[VMState]:
        """Get pending states at a join point."""
        return [state for bucket in self._pending_states.get(pc, {}).values() for state in bucket]

    def clear_pending(self, pc: int) -> None:
        """Clear pending states at a join point."""
        if pc in self._pending_states:
            del self._pending_states[pc]

    def reset(self) -> None:
        """Reset merger state."""
        self._pending_states.clear()
        self.stats = MergeStatistics()


@runtime_checkable
class _ConditionalMergeable(Protocol):
    def conditional_merge(self, other: object, condition: z3.BoolRef) -> object: ...


@runtime_checkable
class _HashableValue(Protocol):
    def hash_value(self) -> int: ...


def _is_any_symbolic(value: object) -> bool:
    from pysymex.core.types.scalars import (
        SymbolicDict,
        SymbolicList,
        SymbolicNone,
        SymbolicObject,
        SymbolicString,
        SymbolicValue,
    )

    return isinstance(
        value,
        (SymbolicValue, SymbolicNone, SymbolicString, SymbolicList, SymbolicDict, SymbolicObject),
    )


def _as_string_object_mapping(value: object | None) -> Mapping[str, object] | None:
    if value is None:
        return {}
    if isinstance(value, dict):
        return (
            cast("Mapping[str, object]", value)
            if all(isinstance(key, str) for key in value)
            else None
        )
    if isinstance(value, CowDict):
        keys = list(value.keys())
        if all(isinstance(key, str) for key in keys):
            return cast("Mapping[str, object]", value)
    return None


def create_state_merger(
    policy: str = "moderate",
    max_constraints: int = 50,
    similarity_threshold: float = 0.7,
) -> StateMerger:
    """Factory function to create a ``StateMerger``.

    Args:
        policy: One of ``"conservative"``, ``"moderate"``, ``"aggressive"``.
        max_constraints: Maximum path constraints allowed for merging.
        similarity_threshold: Minimum similarity for merge eligibility.

    Returns:
        Configured ``StateMerger`` instance.
    """
    policy_map = {
        "conservative": MergePolicy.CONSERVATIVE,
        "moderate": MergePolicy.MODERATE,
        "aggressive": MergePolicy.AGGRESSIVE,
    }
    return StateMerger(
        policy=policy_map.get(policy.lower(), MergePolicy.MODERATE),
        max_constraints_for_merge=max_constraints,
        similarity_threshold=similarity_threshold,
    )
