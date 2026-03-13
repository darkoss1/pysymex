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

from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

import z3

from pysymex.core.copy_on_write import ConstraintChain, CowDict

if TYPE_CHECKING:
    import dis

    from pysymex.core.state import VMState


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
    ):
        self.policy = policy
        self.max_constraints_for_merge = max_constraints_for_merge
        self.similarity_threshold = similarity_threshold
        self.stats = MergeStatistics()
        self._join_points: set[int] = set()
        self._pending_states: dict[int, list[VMState]] = {}

    def set_join_points(self, join_points: set[int]) -> None:
        """Set the CFG join points for merge consideration."""
        self._join_points = join_points

    def detect_join_points(self, instructions: list[dis.Instruction], code: object = None) -> set[int]:
        """Detect join points using CFG analysis for better accuracy."""
        from pysymex.analysis.cfg import CFGBuilder
        
        builder = CFGBuilder()
        # Use CFG to find blocks with multiple predecessors
        cfg = builder.build(code) if code else builder.build_from_instructions(instructions)
        
        self._join_points = {
            block.start_pc for block in cfg.blocks.values() 
            if len(block.predecessors) > 1
        }
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

    def add_state_for_merge(self, state: VMState) -> VMState | None:
        """Add a state for potential merging. Returns merged state or None."""
        pc = state.pc
        if pc not in self._pending_states:
            self._pending_states[pc] = []
        pending = self._pending_states[pc]
        self.stats.states_before_merge += 1
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

    def _can_merge_symbolically(self, state1: VMState, state2: VMState) -> bool:
        """Check if states are compatible for symbolic merging.

        Requirements:
        1. Same PC (obviously)
        2. Same stack depth (structure of execution must match)
        3. Same call stack depth
        4. Same set of local variables (roughly)
        5. Same block stack structure (block_type + handler_pc per entry)
        """
        if state1.pc != state2.pc:
            return False
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
        for b1, b2 in zip(state1.block_stack, state2.block_stack):
            if b1.block_type != b2.block_type or b1.handler_pc != b2.handler_pc:
                return False
        return True

    def _extract_branch_condition(
        self, state1: VMState, state2: VMState
    ) -> tuple[z3.BoolRef | None, int]:
        """Find the condition that distinguishes state1 from state2.
        Returns (condition, common_len).
        """
        cons1 = state1.path_constraints
        cons2 = state2.path_constraints
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

        def _merge_pair(left: object, right: object, merge_condition: z3.BoolRef) -> object | None:
            from pysymex.core.types import SymbolicValue

            # Refuse to merge incompatible container types (e.g. list vs int)
            from pysymex.core.types_containers import (
                SymbolicDict,
                SymbolicList,
                SymbolicObject,
                SymbolicString,
            )
            _CONTAINER_TYPES = (SymbolicList, SymbolicDict, SymbolicString, SymbolicObject)
            left_is_container = isinstance(left, _CONTAINER_TYPES)
            right_is_container = isinstance(right, _CONTAINER_TYPES)
            if left_is_container != right_is_container:
                return None  # incompatible types (e.g. list vs int)
            if left_is_container and right_is_container and type(left) is not type(right):
                return None  # different container types (e.g. list vs dict)


            left_symbolic = (
                left if hasattr(left, "conditional_merge") else SymbolicValue.from_const(left)
            )
            right_symbolic = (
                right if hasattr(right, "conditional_merge") else SymbolicValue.from_const(right)
            )
            try:
                return left_symbolic.conditional_merge(right_symbolic, merge_condition)
            except TypeError:
                return None


        merged = state1.fork()

        new_chain = ConstraintChain.empty()

        common_cons = list(state1.path_constraints[:common_len])
        for c in common_cons:
            new_chain = new_chain.append(c)

        extra1 = state1.path_constraints[common_len:]
        extra2 = state2.path_constraints[common_len:]

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
        merged_stack: list[object] = []
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
            for f1, f2 in zip(state1.call_stack, state2.call_stack):
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

                        merged_frame_locals[k] = v1 or v2

                from dataclasses import replace

                mf = replace(f1, local_vars=merged_frame_locals)
                merged_call_stack.append(mf)
            merged.call_stack = merged_call_stack
        elif state1.call_stack or state2.call_stack:
            return None
        all_addrs = set(state1.memory.keys()) | set(state2.memory.keys())
        merged.memory = CowDict()
        for addr in all_addrs:
            dict1 = state1.memory.get(addr, {})
            dict2 = state2.memory.get(addr, {})
            merged_dict = {}
            all_attrs = set(dict1.keys()) | set(dict2.keys())
            for attr in all_attrs:
                v1 = dict1.get(attr)
                v2 = dict2.get(attr)
                if v1 is not None and v2 is not None:
                    if v1 is v2:
                        merged_dict[attr] = v1
                        continue
                    if hasattr(v1, "hash_value") and hasattr(v2, "hash_value"):
                        if v1.hash_value() == v2.hash_value():
                            merged_dict[attr] = v1
                            continue
                    merged_val = _merge_pair(v1, v2, condition)
                    if merged_val is None:
                        return None
                    merged_dict[attr] = merged_val
                elif v1 is not None:
                    from pysymex.core.types import SymbolicNone

                    merged_val = _merge_pair(v1, SymbolicNone(f"{attr}_missing"), condition)
                    if merged_val is None:
                        return None
                    merged_dict[attr] = merged_val
                elif v2 is not None:
                    from pysymex.core.types import SymbolicNone

                    merged_val = _merge_pair(v2, SymbolicNone(f"{attr}_missing"), z3.Not(condition))
                    if merged_val is None:
                        return None
                    merged_dict[attr] = merged_val
            from pysymex.core.state import wrap_cow_dict

            merged.memory[addr] = wrap_cow_dict(merged_dict)
        return merged

    def _constraints_equal(self, c1: z3.BoolRef, c2: z3.BoolRef) -> bool:
        """Check if two constraints are equivalent."""
        try:
            return z3.eq(c1, c2)
        except z3.Z3Exception:
            return str(c1) == str(c2)

    def get_pending_states(self, pc: int) -> list[VMState]:
        """Get pending states at a join point."""
        return self._pending_states.get(pc, [])

    def clear_pending(self, pc: int) -> None:
        """Clear pending states at a join point."""
        if pc in self._pending_states:
            del self._pending_states[pc]

    def reset(self) -> None:
        """Reset merger state."""
        self._pending_states.clear()
        self.stats = MergeStatistics()


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
