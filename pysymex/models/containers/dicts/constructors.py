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

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicDict,
)
from pysymex.models.builtins.core.helpers import (
    known_iter_type_error,
    resolve_heap_object,
    type_error_side_effect,
)
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    contains_definitely_unhashable_item,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Dictionary constructor-like symbolic models."""


class DictFromkeysModel(FunctionModel):
    """Model for dict.fromkeys(iterable, value)."""

    name = "fromkeys"
    qualname = "dict.fromkeys"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return _fromkeys_type_error(
                state,
                f"dict.fromkeys() received invalid positional argument count: {len(args)}",
            )
        result, constraint = SymbolicDict.symbolic(f"fromkeys_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        keys_arg = resolve_heap_object(args[0], state)
        value: StackValue | None = args[1] if len(args) == 2 else None
        if known_iter_type_error(keys_arg):
            return _fromkeys_type_error(state, "dict.fromkeys() argument is not iterable")
        concrete_keys = concrete_iterable_items(keys_arg, state)
        if concrete_keys is not None:
            if contains_definitely_unhashable_item(concrete_keys, state):
                return _fromkeys_type_error(
                    state, "dict.fromkeys() argument contains an unhashable key"
                )
            return ModelResult(value=SymbolicDict.from_const(dict.fromkeys(concrete_keys, value)))
        keys_len = getattr(keys_arg, "z3_len", None)
        if keys_len is not None:
            constraints.append(result.z3_len == keys_len)
        return ModelResult(value=result, constraints=constraints)


def _fromkeys_type_error(state: VMState, message: str) -> ModelResult:
    result, constraint = SymbolicDict.symbolic(f"fromkeys_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=type_error_side_effect("dict.fromkeys", message),
    )
