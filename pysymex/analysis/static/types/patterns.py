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

"""
Pattern recognition and type state tracking for pysymex's type inference.

Contains:
- PatternRecognizer: Recognizes common Python patterns (dict.get, defaultdict,
  iteration patterns, etc.) that affect type inference
- TypeState: Dataclass tracking type state at a program point
- TypeStateMachine: Manages type state through control flow (branches, loops,
  try/except/finally)
"""

from __future__ import annotations

from pysymex.analysis.static.types.engine.core import TypeInferenceEngine
from pysymex.analysis.static.types.kinds import PyType, TypeKind
from pysymex.analysis.static.types.type_state import TypeState as TypeState
from pysymex.analysis.static.types.type_state import TypeStateMachine as TypeStateMachine


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
