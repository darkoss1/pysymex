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

"""Base types for symbolic function models.

Provides the ``ModelResult`` dataclass and ``FunctionModel`` ABC
that all builtin / stdlib model classes inherit from.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.models.builtins.results import (
    AttributeMutationEffect,
    ModelResult,
    RaisedExceptionEffect,
    SideEffectValue,
    SinkEventEffect,
    is_raised_exception_effect,
    is_sink_event_effect,
    new_side_effects,
    none_model_result,
)


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
        func_name = getattr(func, "__name__", None)
        if isinstance(func_name, str):
            return func_name == self.name
        return str(func) == self.name


class NoneResultFunctionModel(FunctionModel):
    """Base model for side-effect-only functions returning symbolic None."""

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Return symbolic None without adding constraints or side effects."""
        return none_model_result()


__all__ = [
    "AttributeMutationEffect",
    "FunctionModel",
    "ModelResult",
    "NoneResultFunctionModel",
    "RaisedExceptionEffect",
    "SideEffectValue",
    "SinkEventEffect",
    "is_raised_exception_effect",
    "is_sink_event_effect",
    "new_side_effects",
    "none_model_result",
]
