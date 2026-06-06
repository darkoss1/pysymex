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

"""Shared helpers for symbolic dict models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.containers.strings.shared import get_symbolic_string
from pysymex.models.typed_results import symbolic_bool_result, symbolic_int_result

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


def get_symbolic_dict(arg: object, state: VMState | None = None) -> SymbolicDict | None:
    """Extract SymbolicDict from argument, resolving SymbolicObject if needed."""
    if isinstance(arg, SymbolicDict):
        return arg
    if state is not None:
        from pysymex.core.types.containers.objects import SymbolicObject

        if isinstance(arg, SymbolicObject):
            addr = arg.address
            if addr in state.memory:
                val = state.memory[addr]
                if isinstance(val, SymbolicDict):
                    return val
    return None


def dict_type_error_result(name: str, state: VMState) -> ModelResult:
    """Return a deterministic TypeError result for an invalid dict method call."""
    result, constraint = SymbolicValue.symbolic(f"dict_{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "raised_exception": {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": f"dict.{name}() received invalid arguments",
                "source": f"dict.{name}",
            }
        },
    )


__all__ = [
    "FunctionModel",
    "ModelResult",
    "SymbolicDict",
    "SymbolicList",
    "SymbolicNone",
    "SymbolicValue",
    "dict_type_error_result",
    "get_symbolic_dict",
    "get_symbolic_string",
    "symbolic_bool_result",
    "symbolic_int_result",
    "z3",
]
