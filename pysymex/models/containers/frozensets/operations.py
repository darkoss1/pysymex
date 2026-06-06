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

"""Operation symbolic frozenset models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.models.builtins.base import FunctionModel, ModelResult

from .shared import frozenset_type_error_result, get_symbolic_frozenset

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class FrozensetUnionModel(FunctionModel):
    """Model for frozenset.union(*others)."""

    name = "union"
    qualname = "frozenset.union"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args or kwargs:
            return frozenset_type_error_result(self.name, state)
        s = get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"frozenset_union_{state.pc}")
        setattr(result, "_type", "frozenset")
        constraints = [constraint]
        if s is not None:
            constraints.append(result.z3_len >= s.z3_len)
        return ModelResult(value=result, constraints=constraints)


class FrozensetIntersectionModel(FunctionModel):
    """Model for frozenset.intersection(*others)."""

    name = "intersection"
    qualname = "frozenset.intersection"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args or kwargs:
            return frozenset_type_error_result(self.name, state)
        s = get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"frozenset_inter_{state.pc}")
        setattr(result, "_type", "frozenset")
        constraints = [constraint, result.z3_len >= 0]
        if s is not None:
            constraints.append(result.z3_len <= s.z3_len)
        return ModelResult(value=result, constraints=constraints)


class FrozensetDifferenceModel(FunctionModel):
    """Model for frozenset.difference(*others)."""

    name = "difference"
    qualname = "frozenset.difference"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args or kwargs:
            return frozenset_type_error_result(self.name, state)
        s = get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"frozenset_diff_{state.pc}")
        setattr(result, "_type", "frozenset")
        constraints = [constraint, result.z3_len >= 0]
        if s is not None:
            constraints.append(result.z3_len <= s.z3_len)
        return ModelResult(value=result, constraints=constraints)


class FrozensetSymmetricDifferenceModel(FunctionModel):
    """Model for frozenset.symmetric_difference(other)."""

    name = "symmetric_difference"
    qualname = "frozenset.symmetric_difference"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return frozenset_type_error_result(self.name, state)
        result, constraint = SymbolicList.symbolic(f"frozenset_symdiff_{state.pc}")
        setattr(result, "_type", "frozenset")
        constraints = [constraint, result.z3_len >= 0]
        return ModelResult(value=result, constraints=constraints)


class FrozensetCopyModel(FunctionModel):
    """Model for frozenset.copy()."""

    name = "copy"
    qualname = "frozenset.copy"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return frozenset_type_error_result(self.name, state)
        s = get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"frozenset_copy_{state.pc}")
        setattr(result, "_type", "frozenset")
        constraints = [constraint]
        if s is not None:
            constraints.append(result.z3_len == s.z3_len)
        return ModelResult(value=result, constraints=constraints)
