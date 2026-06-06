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
Advanced Type Inference Engine for pysymex.

Slim hub that re-exports type inference components from extraction modules:
- type_kinds: TypeKind enum and PyType dataclass
- type_env: TypeEnvironment scope tracking
- type_engine: TypeInferenceEngine core inference
- type_patterns: PatternRecognizer, TypeState, TypeStateMachine

This module also contains:
- ConfidenceScore: Confidence scoring for type inference results
- TypeAnalyzer: Main integration class combining all components
- get_type_analyzer(): Singleton accessor
"""

from __future__ import annotations

from pysymex.logger import get_logger

logger = get_logger(__name__)

import inspect
import threading
from collections.abc import Callable
from types import CodeType

from pysymex.analysis.static.types.confidence import ConfidenceScore
from pysymex.analysis.static.types.engine.core import TypeInferenceEngine
from pysymex.analysis.static.types.env import TypeEnvironment
from pysymex.analysis.static.types.kinds import PyType, TypeKind
from pysymex.analysis.static.types.patterns import (
    PatternRecognizer,
    TypeState,
    TypeStateMachine,
)


class TypeAnalyzer:
    """
    Main type analysis integration for pysymex.
    Combines:
    - Type inference engine
    - Pattern recognition
    - Type state tracking
    - Confidence scoring
    """

    def __init__(self) -> None:
        self.type_engine = TypeInferenceEngine()
        self.pattern_recognizer = PatternRecognizer(self.type_engine)
        self.state_machine = TypeStateMachine(self.type_engine, self.pattern_recognizer)
        self.confidence_scores: dict[tuple[int, str], ConfidenceScore] = {}
        self.lock = threading.RLock()

    def _reset_run_state(self) -> None:
        """Reset run state."""
        self.state_machine = TypeStateMachine(self.type_engine, self.pattern_recognizer)
        self.confidence_scores = {}

    def analyze_function(
        self,
        func: Callable[..., object] | CodeType,
        initial_types: dict[str, PyType] | None = None,
    ) -> dict[int, TypeEnvironment]:
        """
        Perform type analysis on a function.
        Args:
            func: Function or code object to analyze
            initial_types: Optional initial type assignments
        Returns:
            Mapping from PC to type environment
        """
        with self.lock:
            self._reset_run_state()
            initial_env = TypeEnvironment()

            if isinstance(func, CodeType):
                code = func
                for var in code.co_varnames[: code.co_argcount]:
                    initial_env.set_type(var, PyType.unknown())
            else:
                try:
                    param_types, _return_type = self.type_engine.infer_function_signature(func)
                    sig = inspect.signature(func)
                    for (param_name, _), param_type in zip(
                        sig.parameters.items(), param_types, strict=False
                    ):
                        initial_env.set_type(param_name, param_type)
                except (ValueError, TypeError):
                    logger.debug(
                        "Function signature type inference skipped",
                        exc_info=True,
                    )

            if initial_types:
                for name, typ in initial_types.items():
                    initial_env.set_type(name, typ)

            initial_state = TypeState(env=initial_env, pc=0)
            self.state_machine.set_state(0, initial_state)

            return {pc: state.env for pc, state in self.state_machine.states.items()}

    def get_type_at(self, pc: int, var_name: str) -> PyType:
        """Get type of a variable at a program point."""
        with self.lock:
            state = self.state_machine.get_state(pc)
            if state:
                return state.env.get_type(var_name)
            return PyType.unknown()

    def get_confidence_at(self, pc: int, var_name: str) -> ConfidenceScore:
        """Get confidence score for a variable at a program point."""
        with self.lock:
            key = (pc, var_name)
            return self.confidence_scores.get(key, ConfidenceScore.unknown())

    def is_safe_subscript(
        self,
        pc: int,
        container_var: str,
        index_var: str,
    ) -> tuple[bool, str]:
        """
        Check if a subscript operation is safe.
        Returns:
            (is_safe, reason)
        """
        container_type = self.get_type_at(pc, container_var)
        index_type = self.get_type_at(pc, index_var)
        if container_type.kind == TypeKind.DEFAULTDICT:
            return True, "defaultdict never raises KeyError"
        if not container_type.is_subscriptable():
            return False, f"Type {container_type.name} is not subscriptable"
        if container_type.kind == TypeKind.DICT:
            key_type = container_type.get_key_type()
            if not index_type.is_subtype_of(key_type) and key_type.kind != TypeKind.ANY:
                return (
                    False,
                    f"Key type {index_type.name} doesn't match dict key type {key_type.name}",
                )
        if container_type.kind in {TypeKind.LIST, TypeKind.TUPLE, TypeKind.DEQUE}:
            if index_type.kind != TypeKind.INT and index_type.kind != TypeKind.LITERAL:
                pass
        return True, "No obvious type issue"

    def is_safe_binary_op(
        self,
        pc: int,
        left_var: str,
        right_var: str,
        op: str,
    ) -> tuple[bool, str]:
        """
        Check if a binary operation is type-safe.
        Returns:
            (is_safe, reason)
        """
        left_type = self.get_type_at(pc, left_var)
        right_type = self.get_type_at(pc, right_var)
        if op in {"+", "-", "*", "/", "//", "%", "**"}:
            if left_type.is_numeric() and right_type.is_numeric():
                return True, "Numeric operation"
            if op == "+":
                if left_type.kind == TypeKind.STR and right_type.kind == TypeKind.STR:
                    return True, "String concatenation"
                if left_type.kind == TypeKind.LIST and right_type.kind == TypeKind.LIST:
                    return True, "List concatenation"
                if left_type.kind == TypeKind.STR and right_type.kind != TypeKind.STR:
                    return False, f"Cannot concatenate str with {right_type.name}"
                if left_type.kind != TypeKind.STR and right_type.kind == TypeKind.STR:
                    return False, f"Cannot concatenate {left_type.name} with str"
            if op == "*":
                if left_type.kind == TypeKind.STR and right_type.kind == TypeKind.INT:
                    return True, "String repetition"
                if left_type.kind == TypeKind.INT and right_type.kind == TypeKind.STR:
                    return True, "String repetition"
                if left_type.kind == TypeKind.LIST and right_type.kind == TypeKind.INT:
                    return True, "List repetition"
                if left_type.kind == TypeKind.INT and right_type.kind == TypeKind.LIST:
                    return True, "List repetition"
                if left_type.kind == TypeKind.STR and right_type.kind != TypeKind.INT:
                    return False, f"Cannot multiply str with {right_type.name}"
        if op in {"/", "//", "%"}:
            if right_type.kind == TypeKind.LITERAL:
                for val in right_type.literal_values:
                    if val == 0:
                        return False, "Division by zero literal"
        return True, "No obvious type issue"

    def check_none_dereference(
        self,
        pc: int,
        var_name: str,
    ) -> tuple[bool, str]:
        """
        Check if a variable could be None when dereferenced.
        Returns:
            (could_be_none, reason)
        """
        var_type = self.get_type_at(pc, var_name)
        if var_type.kind == TypeKind.NONE:
            return True, "Variable is always None"
        if var_type.is_nullable():
            return True, "Variable could be None"
        return False, "Variable is not nullable"


_default_type_analyzer: TypeAnalyzer | None = None
_default_type_analyzer_lock = threading.Lock()


def get_type_analyzer() -> TypeAnalyzer:
    """Get the default type analyzer instance."""
    global _default_type_analyzer
    if _default_type_analyzer is None:
        with _default_type_analyzer_lock:
            if _default_type_analyzer is None:
                _default_type_analyzer = TypeAnalyzer()
    return _default_type_analyzer
