"""Base types for symbolic function models.

Provides the ``ModelResult`` dataclass and ``FunctionModel`` ABC
that all builtin / stdlib model classes inherit from.
"""

from __future__ import annotations


from abc import ABC, abstractmethod

from collections.abc import Sequence

from dataclasses import dataclass

from typing import TYPE_CHECKING, Any


import z3

if TYPE_CHECKING:
    from pysymex.core.state import VMState


@dataclass
class ModelResult:
    """Result of a model application."""

    value: Any

    constraints: Sequence[z3.ExprRef | z3.BoolRef] | None = None

    side_effects: dict[str, Any] | None = None

    def __post_init__(self):
        if self.constraints is None:
            self.constraints = []

        if self.side_effects is None:
            self.side_effects = {}


class FunctionModel(ABC):
    """Base class for function models."""

    name: str = "unknown"

    qualname: str = "unknown"

    @abstractmethod
    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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

    def matches(self, func: Any) -> bool:
        """Check if this model matches a given function."""

        if hasattr(func, "__name__"):
            return func.__name__ == self.name

        return str(func) == self.name
