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

"""Pop and clear symbolic set method models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.constants import Z3_ZERO

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicNone,
    SymbolicValue,
    get_symbolic_set,
    replace_exact_set_value,
    set_length_expr,
    set_type_error_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class SetPopModel(FunctionModel):
    """Model for set.pop()."""

    name = "pop"
    qualname = "set.pop"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.pop method."""
        if len(args) != 1 or kwargs:
            return set_type_error_result(self.name, state)
        s = get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"set_pop_{state.pc}")
        constraints: list[z3.BoolRef | z3.ExprRef] = [constraint]
        side_effects: dict[str, object] = {}
        z3_len = set_length_expr(s) if s else None
        if s is not None and z3_len is not None:
            constraints.append(z3_len >= 1)
            side_effects["potential_exception"] = {
                "type": "KeyError",
                "message": "pop from an empty set",
                "condition": z3_len == 0,
            }
            new_len = z3.Int(f"set_len_{state.pc}")
            constraints.append(new_len == z3_len - 1)
            s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "pop",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_decrease": 1,
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class SetClearModel(FunctionModel):
    """Model for set.clear()."""

    name = "clear"
    qualname = "set.clear"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.clear method."""
        if len(args) != 1 or kwargs:
            return set_type_error_result(self.name, state)
        s = get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        if s is not None:
            old_length = set_length_expr(s)
            if isinstance(s.value, set):
                replace_exact_set_value(s, set())
            else:
                s.z3_int = Z3_ZERO
            side_effects["set_mutation"] = {
                "operation": "clear",
                "set_name": getattr(s, "_name", "set"),
                "old_length": old_length,
                "new_length": 0,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )
