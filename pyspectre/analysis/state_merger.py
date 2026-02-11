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
from typing import TYPE_CHECKING, Any
import z3

if TYPE_CHECKING:
    from pyspectre.core.state import VMState


class MergePolicy(Enum):
    """Merge aggressiveness policies."""

    CONSERVATIVE = auto()
    MODERATE = auto()
    AGGRESSIVE = auto()


@dataclass
class MergeStatistics:
    """Statistics about state merging."""

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
    """Abstract information about a variable."""

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

    def detect_join_points(self, instructions: list) -> set[int]:
        """Detect join points from instruction list by finding branch targets."""
        join_points: set[int] = set()
        branch_targets: dict[int, int] = {}
        for i, instr in enumerate(instructions):
            if instr.opname in (
                "JUMP_FORWARD",
                "JUMP_BACKWARD",
                "JUMP_ABSOLUTE",
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_FORWARD_IF_TRUE",
                "POP_JUMP_FORWARD_IF_FALSE",
                "POP_JUMP_BACKWARD_IF_TRUE",
                "POP_JUMP_BACKWARD_IF_FALSE",
                "JUMP_IF_TRUE_OR_POP",
                "JUMP_IF_FALSE_OR_POP",
                "FOR_ITER",
            ):
                target = instr.argval if instr.argval else instr.arg
                if target is not None:
                    branch_targets[target] = branch_targets.get(target, 0) + 1
        for target, count in branch_targets.items():
            if count >= 1:
                for i, instr in enumerate(instructions):
                    if instr.offset == target:
                        join_points.add(i)
                        break
        self._join_points = join_points
        return join_points

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
        return True

    def _extract_branch_condition(self, state1: VMState, state2: VMState) -> z3.BoolRef | None:
        """Find the condition that distinguishes state1 from state2.

        Assumption: They share a common prefix of constraints, and then diverge.
        state1: Common + [Cond]
        state2: Common + [Not(Cond)]
        """
        cons1 = state1.path_constraints
        cons2 = state2.path_constraints
        common_len = 0
        min_len = min(len(cons1), len(cons2))
        while common_len < min_len:
            if not self._constraints_equal(cons1[common_len], cons2[common_len]):
                break
            common_len += 1
        if common_len == len(cons1) - 1 and common_len == len(cons2) - 1:
            c1 = cons1[common_len]
            c2 = cons2[common_len]
            return c1
        return None

    def _merge_states_symbolically(self, state1: VMState, state2: VMState) -> VMState | None:
        """Merge states by creating conditional symbolic values."""
        condition = self._extract_branch_condition(state1, state2)
        if condition is None:
            return None
        merged = state1.fork()
        common_len = len(state1.path_constraints) - 1
        merged.path_constraints = list(state1.path_constraints[:common_len])
        for name in state1.local_vars:
            val1 = state1.local_vars[name]
            val2 = state2.local_vars[name]
            from pyspectre.core.types import SymbolicValue

            s1 = val1 if hasattr(val1, "conditional_merge") else SymbolicValue.from_const(val1)
            s2 = val2 if hasattr(val2, "conditional_merge") else SymbolicValue.from_const(val2)
            merged.local_vars[name] = s1.conditional_merge(s2, condition)
        merged_stack = []
        for i in range(len(state1.stack)):
            val1 = state1.stack[i]
            val2 = state2.stack[i]
            from pyspectre.core.types import SymbolicValue

            s1 = val1 if hasattr(val1, "conditional_merge") else SymbolicValue.from_const(val1)
            s2 = val2 if hasattr(val2, "conditional_merge") else SymbolicValue.from_const(val2)
            merged_stack.append(s1.conditional_merge(s2, condition))
        merged.stack = merged_stack
        linking_constraints = []
        all_addrs = set(state1.memory.keys()) | set(state2.memory.keys())
        merged.memory = {}
        for addr in all_addrs:
            dict1 = state1.memory.get(addr, {})
            dict2 = state2.memory.get(addr, {})
            merged_dict = {}
            all_attrs = set(dict1.keys()) | set(dict2.keys())
            for attr in all_attrs:
                v1 = dict1.get(attr)
                v2 = dict2.get(attr)
                from pyspectre.core.types import SymbolicValue

                if v1 is not None and v2 is not None:
                    s1 = v1 if hasattr(v1, "conditional_merge") else SymbolicValue.from_const(v1)
                    s2 = v2 if hasattr(v2, "conditional_merge") else SymbolicValue.from_const(v2)
                    merged_val = s1.conditional_merge(s2, condition)
                    merged_dict[attr] = merged_val
                    if (
                        hasattr(merged_val, "z3_int")
                        and hasattr(s1, "z3_int")
                        and hasattr(s2, "z3_int")
                    ):
                        linking_constraints.append(
                            z3.Implies(condition, merged_val.z3_int == s1.z3_int)
                        )
                        linking_constraints.append(
                            z3.Implies(z3.Not(condition), merged_val.z3_int == s2.z3_int)
                        )
                elif v1 is not None:
                    s1 = v1 if hasattr(v1, "conditional_merge") else SymbolicValue.from_const(v1)
                    from pyspectre.core.types import SymbolicNone

                    merged_val = s1.conditional_merge(SymbolicNone(), condition)
                    merged_dict[attr] = merged_val
                    if hasattr(merged_val, "z3_int") and hasattr(s1, "z3_int"):
                        linking_constraints.append(
                            z3.Implies(condition, merged_val.z3_int == s1.z3_int)
                        )
                elif v2 is not None:
                    s2 = v2 if hasattr(v2, "conditional_merge") else SymbolicValue.from_const(v2)
                    from pyspectre.core.types import SymbolicNone

                    merged_val = s2.conditional_merge(SymbolicNone(), z3.Not(condition))
                    merged_dict[attr] = merged_val
                    if hasattr(merged_val, "z3_int") and hasattr(s2, "z3_int"):
                        linking_constraints.append(
                            z3.Implies(z3.Not(condition), merged_val.z3_int == s2.z3_int)
                        )
            merged.memory[addr] = merged_dict
        for lc in linking_constraints:
            merged.path_constraints.append(lc)
        return merged

    def _constraints_equal(self, c1: z3.BoolRef, c2: z3.BoolRef) -> bool:
        """Check if two constraints are equivalent."""
        try:
            return z3.eq(c1, c2)
        except Exception:
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
    """Factory function to create a StateMerger."""
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
