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

"""Relation symbolic frozenset models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult

from .shared import frozenset_type_error_result, get_symbolic_frozenset

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class FrozensetIssubsetModel(FunctionModel):
    """Model for frozenset.issubset(other)."""

    name = "issubset"
    qualname = "frozenset.issubset"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return frozenset_type_error_result(self.name, state)
        s = get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"frozenset_issubset_{state.pc}")
        constraints = [constraint, result.is_bool]
        if s is not None:
            constraints.append(z3.Implies(s.z3_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)


class FrozensetIssupersetModel(FunctionModel):
    """Model for frozenset.issuperset(other)."""

    name = "issuperset"
    qualname = "frozenset.issuperset"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return frozenset_type_error_result(self.name, state)
        result, constraint = SymbolicValue.symbolic(f"frozenset_issuperset_{state.pc}")
        constraints = [constraint, result.is_bool]
        return ModelResult(value=result, constraints=constraints)


class FrozensetIsdisjointModel(FunctionModel):
    """Model for frozenset.isdisjoint(other)."""

    name = "isdisjoint"
    qualname = "frozenset.isdisjoint"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return frozenset_type_error_result(self.name, state)
        s = get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"frozenset_isdisjoint_{state.pc}")
        constraints = [constraint, result.is_bool]
        if s is not None:
            constraints.append(z3.Implies(s.z3_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)
