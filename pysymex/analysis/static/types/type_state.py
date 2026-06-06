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

"""Control-flow-sensitive type state tracking variables to inferred types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex.analysis.static.types.engine.core import TypeInferenceEngine
from pysymex.analysis.static.types.env import TypeEnvironment
from pysymex.analysis.static.types.kinds import PyType

if TYPE_CHECKING:
    from pysymex.analysis.static.types.patterns import PatternRecognizer


@dataclass
class TypeState:
    """
    Represents type state at a program point.
    Tracks:
    - Variable types
    - Refinements from control flow
    - Definitely/maybe assigned
    """

    env: TypeEnvironment
    pc: int = 0
    in_try_block: bool = False
    in_except_block: bool = False
    in_finally_block: bool = False
    loop_depth: int = 0
    in_loop_body: bool = False
    branch_condition: str | None = None
    positive_branch: bool = True

    def copy(self) -> TypeState:
        """Create a copy of this state."""
        return TypeState(
            env=self.env.copy(),
            pc=self.pc,
            in_try_block=self.in_try_block,
            in_except_block=self.in_except_block,
            in_finally_block=self.in_finally_block,
            loop_depth=self.loop_depth,
            in_loop_body=self.in_loop_body,
            branch_condition=self.branch_condition,
            positive_branch=self.positive_branch,
        )

    def join(self, other: TypeState) -> TypeState:
        """Join two states at a merge point."""
        return TypeState(
            env=self.env.join(other.env),
            pc=max(self.pc, other.pc),
            in_try_block=self.in_try_block or other.in_try_block,
            in_except_block=self.in_except_block or other.in_except_block,
            in_finally_block=self.in_finally_block or other.in_finally_block,
            loop_depth=max(self.loop_depth, other.loop_depth),
            in_loop_body=self.in_loop_body or other.in_loop_body,
        )


class TypeStateMachine:
    """
    Tracks type state through control flow.
    Handles:
    - If/else branches with type narrowing
    - Loop iterations with widening
    - Try/except/finally blocks
    - Function calls and returns
    """

    def __init__(
        self,
        type_engine: TypeInferenceEngine,
        pattern_recognizer: PatternRecognizer,
    ) -> None:
        self.type_engine = type_engine
        self.pattern_recognizer = pattern_recognizer
        self.states: dict[int, TypeState] = {}
        self.pending: list[TypeState] = []

    def get_state(self, pc: int) -> TypeState | None:
        """Get type state at a program point."""
        return self.states.get(pc)

    def set_state(self, pc: int, state: TypeState) -> None:
        """Set type state at a program point."""
        self.states[pc] = state

    def enter_branch(
        self,
        state: TypeState,
        condition_var: str,
        condition_type: PyType,
        positive: bool,
    ) -> TypeState:
        """
        Enter a branch with type narrowing.
        Args:
            state: Current state
            condition_var: Variable in condition
            condition_type: Type from condition (e.g., the class in isinstance)
            positive: True for if branch, False for else branch
        Returns:
            New state with narrowed types
        """
        new_state = state.copy()
        new_state.branch_condition = condition_var
        new_state.positive_branch = positive
        current_type = new_state.env.get_type(condition_var)
        narrowed = self.type_engine.narrow_type_for_isinstance(
            current_type, condition_type, positive
        )
        new_state.env.refine_type(condition_var, narrowed)
        return new_state

    def enter_none_branch(
        self,
        state: TypeState,
        var_name: str,
        is_none: bool,
    ) -> TypeState:
        """Enter a branch after None check."""
        new_state = state.copy()
        current_type = new_state.env.get_type(var_name)
        narrowed = self.type_engine.narrow_type_for_none_check(current_type, is_none)
        new_state.env.refine_type(var_name, narrowed)
        return new_state

    def enter_truthiness_branch(
        self,
        state: TypeState,
        var_name: str,
        is_truthy: bool,
    ) -> TypeState:
        """Enter a branch after truthiness check."""
        new_state = state.copy()
        current_type = new_state.env.get_type(var_name)
        narrowed = self.type_engine.narrow_type_for_truthiness(current_type, is_truthy)
        new_state.env.refine_type(var_name, narrowed)
        return new_state

    def merge_branches(
        self,
        states: list[TypeState],
    ) -> TypeState:
        """Merge states from multiple branches."""
        if not states:
            raise ValueError("Cannot merge empty state list")
        if len(states) == 1:
            result = states[0].copy()
            result.env.refinements.clear()
            return result
        result = states[0]
        for state in states[1:]:
            result = result.join(state)
        result.env.refinements.clear()
        return result

    def enter_loop(self, state: TypeState) -> TypeState:
        """Enter a loop body."""
        new_state = state.copy()
        new_state.loop_depth += 1
        new_state.in_loop_body = True
        return new_state

    def exit_loop(self, state: TypeState) -> TypeState:
        """Exit a loop body."""
        new_state = state.copy()
        new_state.loop_depth = max(0, new_state.loop_depth - 1)
        new_state.in_loop_body = new_state.loop_depth > 0
        return new_state

    def widen_loop_state(
        self,
        before: TypeState,
        after: TypeState,
    ) -> TypeState:
        """Apply widening for loop convergence."""
        result = after.copy()
        for var in set(before.env.types.keys()) | set(after.env.types.keys()):
            before_type = before.env.get_type(var)
            after_type = after.env.get_type(var)
            if before_type != after_type:
                result.env.types[var] = before_type.join(after_type)
        return result

    def enter_try_block(self, state: TypeState) -> TypeState:
        """Enter a try block."""
        new_state = state.copy()
        new_state.in_try_block = True
        return new_state

    def enter_except_block(
        self,
        state: TypeState,
        exception_var: str | None = None,
        exception_type: PyType | None = None,
    ) -> TypeState:
        """Enter an except block."""
        new_state = state.copy()
        new_state.in_try_block = False
        new_state.in_except_block = True
        if exception_var and exception_type:
            new_state.env.set_type(exception_var, exception_type)
        return new_state

    def enter_finally_block(self, state: TypeState) -> TypeState:
        """Enter a finally block."""
        new_state = state.copy()
        new_state.in_try_block = False
        new_state.in_except_block = False
        new_state.in_finally_block = True
        return new_state

    def exit_exception_handling(self, state: TypeState) -> TypeState:
        """Exit exception handling blocks."""
        new_state = state.copy()
        new_state.in_try_block = False
        new_state.in_except_block = False
        new_state.in_finally_block = False
        return new_state
