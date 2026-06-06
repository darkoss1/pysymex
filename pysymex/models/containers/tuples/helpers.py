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

"""Shared helpers for tuple container models."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import ModelResult

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


def get_symbolic_tuple(arg: object) -> SymbolicList | None:
    """Extract SymbolicList (used for tuples) from argument."""
    if isinstance(arg, SymbolicList):
        return arg
    if isinstance(arg, tuple):
        values = cast("tuple[object, ...]", arg)
        return dataclasses.replace(SymbolicList.from_const(values), _type="tuple")
    return getattr(arg, "_symbolic_list", None) if arg is not None else None


def tuple_type_error_result(name: str, state: VMState) -> ModelResult:
    """Return a deterministic TypeError result for an invalid tuple method call."""
    result, constraint = SymbolicValue.symbolic(f"tuple_{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "raised_exception": {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": f"tuple.{name}() received invalid arguments",
                "source": f"tuple.{name}",
            }
        },
    )
