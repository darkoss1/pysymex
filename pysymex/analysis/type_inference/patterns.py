"""
Pattern recognition and type state tracking for PySyMex's type inference.

Contains:
- PatternRecognizer: Recognizes common Python patterns (dict.get, defaultdict,
  iteration patterns, etc.) that affect type inference
- TypeState: Dataclass tracking type state at a program point
- TypeStateMachine: Manages type state through control flow (branches, loops,
  try/except/finally)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from pysymex.analysis.type_inference.engine import TypeInferenceEngine
from pysymex.analysis.type_inference.env import TypeEnvironment
from pysymex.analysis.type_inference.kinds import PyType, TypeKind


class PatternRecognizer:
    """
    Recognizes common Python patterns that affect type inference.
    Patterns recognized:
    - defaultdict usage
    - dict.get() with default
    - isinstance() checks
    - None checks (is None, is not None)
    - Type guards
    - Container membership tests
    - Exception handling
    """

    def __init__(self, type_engine: TypeInferenceEngine) -> None:
        self.type_engine = type_engine

    def is_dict_get_pattern(
        self,
        callee_type: PyType,
        method_name: str,
        args: list[PyType],
    ) -> PyType | None:
        """
        Recognize dict.get() pattern.
        dict.get(key) returns Optional[V]
        dict.get(key, default) returns V | type(default)
        """
        if callee_type.kind not in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            return None
        if method_name != "get":
            return None
        val_type = callee_type.get_value_type()
        if len(args) == 1:
            return PyType.optional_(val_type)
        if len(args) >= 2:
            default_type = args[1]
            return val_type.join(default_type)
        return None

    def is_defaultdict_pattern(
        self,
        container_type: PyType,
    ) -> bool:
        """Check if this is a defaultdict (no KeyError on missing keys)."""
        return container_type.kind == TypeKind.DEFAULTDICT

    def is_safe_dict_access(
        self,
        container_type: PyType,
        access_method: str,
    ) -> bool:
        """
        Check if dictionary access is safe (won't raise KeyError).
        Safe patterns:
        - defaultdict[key]
        - dict.get(key)
        - dict.get(key, default)
        - dict.setdefault(key, default)
        - key in dict before dict[key]
        """
        if container_type.kind == TypeKind.DEFAULTDICT:
            return True
        if access_method in {"get", "setdefault", "pop"}:
            return True
        return False

    def is_membership_guard(
        self,
        guard_var: str,
        guarded_var: str,
        container_var: str,
    ) -> bool:
        """
        Check if a variable access is guarded by a membership test.
        Pattern: if key in dict: dict[key]
        """
        return guard_var == guarded_var

    def recognize_iteration_pattern(
        self,
        container_type: PyType,
    ) -> PyType | None:
        """
        Recognize type of iteration variable.
        for x in list[T]: x is T
        for k in dict[K, V]: k is K
        for k, v in dict.items(): k is K, v is V
        """
        if container_type.kind == TypeKind.LIST:
            return container_type.get_element_type()
        if container_type.kind == TypeKind.SET:
            return container_type.get_element_type()
        if container_type.kind == TypeKind.TUPLE:
            if container_type.params:
                return PyType.union_(*container_type.params)
            return PyType.any_()
        if container_type.kind in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            return container_type.get_key_type()
        if container_type.kind == TypeKind.STR:
            return PyType.str_()
        if container_type.kind == TypeKind.DEQUE:
            return container_type.get_element_type()
        return None

    def recognize_dict_items_pattern(
        self,
        container_type: PyType,
        method_name: str,
    ) -> tuple[PyType, PyType] | None:
        """
        Recognize dict.items() iteration pattern.
        for k, v in dict.items(): returns (K, V)
        """
        if container_type.kind not in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            return None
        if method_name != "items":
            return None
        return (container_type.get_key_type(), container_type.get_value_type())

    def is_string_operation_safe(
        self,
        left_type: PyType,
        right_type: PyType,
        op: str,
    ) -> bool:
        """
        Check if a string operation is type-safe.
        Safe: str + str, str * int, int * str
        Unsafe: str + int, str - str
        """
        if op == "+":
            return left_type.kind == TypeKind.STR and right_type.kind == TypeKind.STR
        if op == "*":
            return (left_type.kind == TypeKind.STR and right_type.kind == TypeKind.INT) or (
                left_type.kind == TypeKind.INT and right_type.kind == TypeKind.STR
            )
        return False


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
        self.branch_narrowings: dict[int, dict[str, PyType]] = defaultdict(dict)

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
