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

"""Shared interface for models of Python type objects."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pysymex._internal.models.contracts.results import ModelDegradation, SideEffects

if TYPE_CHECKING:
    from collections.abc import Sequence

    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class TypeModelResult:
    """Result of a type model application, including explicit limitations."""

    value: StackValue
    constraints: Sequence[z3.ExprRef | z3.BoolRef] = field(default_factory=tuple)
    side_effects: dict[str, object] = field(default_factory=SideEffects.empty)
    degradations: Sequence[ModelDegradation] = field(default_factory=tuple)


class TypeModel(ABC):
    """Base class for type object models.

    Unlike FunctionModel which models callable functions, TypeModel models
    type objects (classes) that can be referenced, used in isinstance(),
    or instantiated.
    """

    name: str = "unknown"
    qualname: str = "unknown"
    python_type: type | None = None

    @abstractmethod
    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> TypeModelResult:
        """Apply the type model (e.g., for instantiation or type checking).

        Args:
            args: Positional arguments (for instantiation)
            kwargs: Keyword arguments (for instantiation)
            state: Current VM state
        Returns:
            TypeModelResult with symbolic result and any constraints.

        """

    def matches(self, obj: object) -> bool:
        """Check if this model matches a given type object."""
        if self.python_type is not None:
            return obj is self.python_type
        obj_name = getattr(obj, "__name__", None)
        if isinstance(obj_name, str):
            return obj_name == self.name
        return str(obj) == self.name
