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

"""len() builtin model."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.common.builtin_policies import BuiltinInputPolicy
from pysymex._internal.core.types.containers.sequence_precision import (
    derived_concrete_items,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


class LenModel(FunctionModel):
    """Model for len()."""

    name = "len"
    qualname = "builtins.len"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply len() model."""
        if len(args) != 1 or kwargs:
            result, constraint = SymbolicValue.symbolic(f"len_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.len",
                    f"len() takes exactly one argument ({len(args)} given)",
                ),
            )
        obj = SymbolicObject.resolve(args[0], state)
        concrete_len = BuiltinInputPolicy.constant_len(obj)
        if concrete_len is not None:
            return ModelResult(value=concrete_len)
        if BuiltinInputPolicy.len_type_error(obj):
            result, constraint = SymbolicValue.symbolic(f"len_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.len",
                    f"object of type '{getattr(obj, 'type_tag', type(obj).__name__)}' has no len()",
                ),
            )
        if isinstance(obj, SymbolicList):
            derived_items = derived_concrete_items(obj, state.path_constraints.to_list())
            if derived_items is not None:
                return ModelResult(value=len(derived_items))
            result, constraints = ModelResult.symbolic_int(f"len_{obj.name}")
            constraints.extend([result.z3_int == obj.z3_len, result.z3_int >= 0])
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if isinstance(obj, SymbolicString):
            result, constraints = ModelResult.symbolic_int(f"len_{obj.name}")
            constraints.extend([result.z3_int == obj.z3_len, result.z3_int >= 0])
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if isinstance(obj, SymbolicBytes):
            result, constraints = ModelResult.symbolic_int(f"len_{obj.name}")
            constraints.extend([result.z3_int == obj.z3_len, result.z3_int >= 0])
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if (
            getattr(obj, "_type", "") == "set"
            or "set" in getattr(obj, "_name", "").lower()
            or getattr(obj, "type_tag", "") == "dict"
            or isinstance(obj, SymbolicDict)
        ):
            z3_len = getattr(obj, "z3_len", getattr(obj, "z3_int", None))
            if z3_len is not None:
                result, constraints = ModelResult.symbolic_int(
                    f"len_{getattr(obj, '_name', 'container')}",
                )
                constraints.append(result.z3_int == z3_len)
                return ModelResult(
                    value=result,
                    constraints=constraints,
                )
        result, base_constraints = ModelResult.symbolic_int(f"len_{state.pc}")
        extra_constraints: list[z3.ExprRef | z3.BoolRef] = [
            *base_constraints,
            result.z3_int >= 0,
        ]

        if isinstance(obj, SymbolicValue):
            extra_constraints.append(z3.Implies(obj.could_be_truthy(), result.z3_int > 0))
            extra_constraints.append(z3.Implies(obj.could_be_falsy(), result.z3_int == 0))
        return ModelResult(
            value=result,
            constraints=extra_constraints,
        )
