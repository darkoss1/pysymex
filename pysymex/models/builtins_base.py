"""Base types for symbolic function models.

Provides the ``ModelResult`` dataclass and ``FunctionModel`` ABC
that all builtin / stdlib model classes inherit from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


@dataclass(frozen=True, slots=True)
class ModelResult:
    """Result of a model application."""

    value: StackValue
    constraints: Sequence[z3.ExprRef | z3.BoolRef] = field(default_factory=tuple)
    side_effects: dict[str, object] = field(default_factory=dict)


class FunctionModel(ABC):
    """Base class for function models."""

    name: str = "unknown"
    qualname: str = "unknown"

    @abstractmethod
    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """
        Apply the function model.
        Args:
            args: Positional arguments
            kwargs: Keyword arguments
            state: Current VM state
        Returns:
            ModelResult with symbolic result and any constraints
        """

    def matches(self, func: object) -> bool:
        """Check if this model matches a given function."""
        if hasattr(func, "__name__"):
            return func.__name__ == self.name
        return str(func) == self.name
