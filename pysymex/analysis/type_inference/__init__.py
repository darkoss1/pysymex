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

import logging

logger = logging.getLogger(__name__)

import inspect
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pysymex.analysis.type_inference.engine import TypeInferenceEngine
from pysymex.analysis.type_inference.env import TypeEnvironment
from pysymex.analysis.type_inference.kinds import PyType, TypeKind
from pysymex.analysis.type_inference.patterns import (
    PatternRecognizer,
    TypeState,
    TypeStateMachine,
)

__all__ = [
    "ConfidenceScore",
    "PatternRecognizer",
    "PyType",
    "TypeAnalyzer",
    "TypeEnvironment",
    "TypeInferenceEngine",
    "TypeKind",
    "TypeState",
    "TypeStateMachine",
    "get_type_analyzer",
]


@dataclass
class ConfidenceScore:
    """
    Confidence score for type inference.
    Factors:
    - Source reliability (annotation > inference > unknown)
    - Path length (shorter paths = higher confidence)
    - Corroboration (multiple sources agreeing)
    - Narrowing (type guards increase confidence)
    """

    score: float
    source: str
    factors: dict[str, float] = field(default_factory=dict[str, float])

    @classmethod
    def from_annotation(cls) -> ConfidenceScore:
        """High confidence from explicit annotation."""
        return cls(
            score=0.95,
            source="annotation",
            factors={"explicit": 0.95},
        )

    @classmethod
    def from_literal(cls) -> ConfidenceScore:
        """Very high confidence from literal value."""
        return cls(
            score=0.99,
            source="literal",
            factors={"literal": 0.99},
        )

    @classmethod
    def from_inference(cls, reliability: float = 0.7) -> ConfidenceScore:
        """Medium confidence from inference."""
        return cls(
            score=reliability,
            source="inferred",
            factors={"inference": reliability},
        )

    @classmethod
    def from_isinstance_guard(cls) -> ConfidenceScore:
        """High confidence from isinstance check."""
        return cls(
            score=0.9,
            source="isinstance_guard",
            factors={"type_guard": 0.9},
        )

    @classmethod
    def from_none_check(cls) -> ConfidenceScore:
        """High confidence from None check."""
        return cls(
            score=0.9,
            source="none_check",
            factors={"none_guard": 0.9},
        )

    @classmethod
    def unknown(cls) -> ConfidenceScore:
        """Low confidence for unknown."""
        return cls(
            score=0.3,
            source="unknown",
            factors={"unknown": 0.3},
        )

    def combine(self, other: ConfidenceScore) -> ConfidenceScore:
        """Combine confidence scores."""
        combined_score = min(self.score, other.score)
        combined_factors = {**self.factors, **other.factors}
        return ConfidenceScore(
            score=combined_score,
            source=f"{self .source }+{other .source }",
            factors=combined_factors,
        )

    def boost_from_guard(self, boost: float = 0.1) -> ConfidenceScore:
        """Boost confidence from a type guard."""
        new_score = min(1.0, self.score + boost)
        return ConfidenceScore(
            score=new_score,
            source=self.source,
            factors={**self.factors, "guard_boost": boost},
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
        """Init."""
        """Initialize the class instance."""
        self.type_engine = TypeInferenceEngine()
        self.pattern_recognizer = PatternRecognizer(self.type_engine)
        self.state_machine = TypeStateMachine(self.type_engine, self.pattern_recognizer)
        self.confidence_scores: dict[tuple[int, str], ConfidenceScore] = {}
        self._lock = threading.RLock()

    def _reset_run_state(self) -> None:
        """Reset run state."""
        self.state_machine = TypeStateMachine(self.type_engine, self.pattern_recognizer)
        self.confidence_scores = {}

    def analyze_function(
        self,
        func: Callable[..., object] | Any,
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
        with self._lock:
            self._reset_run_state()
            initial_env = TypeEnvironment()

            if hasattr(func, "co_code"):
                code: object = func
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
                    pass  # Used as expected type-check or feature fallback

            if initial_types:
                for name, typ in initial_types.items():
                    initial_env.set_type(name, typ)

            initial_state = TypeState(env=initial_env, pc=0)
            self.state_machine.set_state(0, initial_state)

            return {pc: state.env for pc, state in self.state_machine.states.items()}

    def get_type_at(self, pc: int, var_name: str) -> PyType:
        """Get type of a variable at a program point."""
        with self._lock:
            state = self.state_machine.get_state(pc)
            if state:
                return state.env.get_type(var_name)
            return PyType.unknown()

    def get_confidence_at(self, pc: int, var_name: str) -> ConfidenceScore:
        """Get confidence score for a variable at a program point."""
        with self._lock:
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
            return False, f"Type {container_type .name } is not subscriptable"
        if container_type.kind == TypeKind.DICT:
            key_type = container_type.get_key_type()
            if not index_type.is_subtype_of(key_type) and key_type.kind != TypeKind.ANY:
                return (
                    False,
                    f"Key type {index_type .name } doesn't match dict key type {key_type .name }",
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
                    return False, f"Cannot concatenate str with {right_type .name }"
                if left_type.kind != TypeKind.STR and right_type.kind == TypeKind.STR:
                    return False, f"Cannot concatenate {left_type .name } with str"
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
                    return False, f"Cannot multiply str with {right_type .name }"
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
