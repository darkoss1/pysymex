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

"""Query symbolic frozenset models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.containers.sequence_precision import (
    retained_sequence_contains_value,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

from .shared import get_symbolic_frozenset

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class FrozensetContainsModel(FunctionModel):
    """Model for frozenset.__contains__(elem)."""

    name = "__contains__"
    qualname = "frozenset.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = get_symbolic_frozenset(args[0]) if args else None
        if s is not None:
            retained_contains = retained_sequence_contains_value(
                s,
                args[1] if len(args) > 1 else None,
                state.path_constraints.to_list(),
            )
            if retained_contains is not None:
                return ModelResult(value=retained_contains)
        result, constraint = SymbolicValue.symbolic_bool(f"frozenset_contains_{state.pc}")
        constraints = [constraint]
        if s is not None:
            constraints.append(z3.Implies(s.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class FrozensetLenModel(FunctionModel):
    """Model for len(frozenset)."""

    name = "__len__"
    qualname = "frozenset.__len__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = get_symbolic_frozenset(args[0]) if args else None
        if s is not None:
            result = SymbolicValue(
                _name=f"len_frozenset_{state.pc}",
                z3_int=s.z3_len,
                is_int=Z3_TRUE,
                z3_bool=Z3_FALSE,
                is_bool=Z3_FALSE,
            )
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic_int(f"frozenset_len_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_int >= 0])


class FrozensetHashModel(FunctionModel):
    """Model for frozenset.__hash__()."""

    name = "__hash__"
    qualname = "frozenset.__hash__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_int(f"frozenset_hash_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
