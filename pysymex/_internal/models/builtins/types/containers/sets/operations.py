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

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.set_retention import set_length_expr
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

from .shared import get_symbolic_set

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Non-mutating symbolic set operation models."""


class SetCopyModel(FunctionModel):
    """Model for set.copy()."""

    name = "copy"
    qualname = "set.copy"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.copy method."""
        if len(args) != 1 or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"set_copy_{state.pc}")
        result.set_runtime_type("set")
        constraints = [constraint]
        if s is not None:
            z3_len = set_length_expr(s)
            if z3_len is not None:
                constraints.append(result.z3_len == z3_len)
        return ModelResult(value=result, constraints=constraints)


class SetUnionModel(FunctionModel):
    """Model for set.union(*others)."""

    name = "union"
    qualname = "set.union"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.union method."""
        if not args or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"set_union_{state.pc}")
        result.set_runtime_type("set")
        constraints = [constraint]
        if s is not None:
            z3_len = set_length_expr(s)
            if z3_len is not None:
                constraints.append(result.z3_len >= z3_len)
        return ModelResult(value=result, constraints=constraints)


class SetIntersectionModel(FunctionModel):
    """Model for set.intersection(*others)."""

    name = "intersection"
    qualname = "set.intersection"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.intersection method."""
        if not args or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"set_inter_{state.pc}")
        result.set_runtime_type("set")
        constraints = [constraint]
        if s is not None:
            z3_len = set_length_expr(s)
            if z3_len is not None:
                constraints.append(result.z3_len <= z3_len)
                constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class SetDifferenceModel(FunctionModel):
    """Model for set.difference(*others)."""

    name = "difference"
    qualname = "set.difference"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.difference method."""
        if not args or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"set_diff_{state.pc}")
        result.set_runtime_type("set")
        constraints = [constraint]
        if s is not None:
            z3_len = set_length_expr(s)
            if z3_len is not None:
                constraints.append(result.z3_len <= z3_len)
                constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class SetSymDiffModel(FunctionModel):
    """Model for set.symmetric_difference(other)."""

    name = "symmetric_difference"
    qualname = "set.symmetric_difference"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.symmetric_difference method."""
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        other = get_symbolic_set(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"set_symdiff_{state.pc}")
        result.set_runtime_type("set")
        constraints = [constraint, result.z3_len >= 0]
        if s is not None:
            z3_len = set_length_expr(s)
            if z3_len is not None and other is not None:
                other_len = getattr(other, "z3_len", getattr(other, "z3_int", None))
                if other_len is not None:
                    constraints.append(result.z3_len <= z3_len + other_len)
        return ModelResult(value=result, constraints=constraints)
