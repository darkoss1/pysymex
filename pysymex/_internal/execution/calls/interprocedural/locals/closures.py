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

"""Closure-cell capture for nested interprocedural calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    import types

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

logger = get_logger(__name__)


def copy_closure_cells(
    state: VMState,
    func_obj: object,
    func_code: types.CodeType,
    func_name: object,
    symbolic_closure: tuple[object, ...],
    new_locals: dict[str, StackValue],
) -> VMState:
    """Copy closure cells into heap-backed symbolic cell objects."""
    try:
        closure = symbolic_closure or getattr(func_obj, "__closure__", None)
        freevars = list(getattr(func_code, "co_freevars", ()))
        if closure and freevars:
            for fv_name, cell in zip(freevars, closure, strict=False):
                if isinstance(cell, SymbolicObject) and cell.name.startswith("cell_"):
                    new_locals[fv_name] = cell
                else:
                    try:
                        content = getattr(cell, "cell_contents")  # noqa: B009
                    except ValueError:
                        content = SymbolicNoneType()
                    except AttributeError:
                        content = cell
                    addr = next_address()
                    state = state.store_heap(addr, cast("StackValue", content))
                    new_locals[fv_name] = SymbolicObject(
                        f"cell_{fv_name}",
                        addr,
                        ConstraintValues.int(addr),
                        {addr},
                    )
    except (AttributeError, TypeError):
        logger.debug("Unable to copy closure cells for %s", func_name)
    return state
