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

"""Shared coercion for concrete iterator items pushed onto the VM stack."""

from __future__ import annotations

from typing import cast

import z3

from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue

from pysymex.typing import StackValue


def stack_value_from_concrete_iter_item(item: object) -> StackValue:
    """Coerce a concrete iteration element into a VM stack value."""
    if isinstance(
        item,
        (
            SymbolicValue,
            SymbolicNone,
            SymbolicString,
            SymbolicList,
            SymbolicDict,
            SymbolicObject,
            z3.ExprRef,
            int,
            bool,
            str,
            float,
            bytes,
            list,
            tuple,
            type,
        ),
    ):
        return cast("StackValue", item)
    return SymbolicValue.from_const(item)


__all__ = ["stack_value_from_concrete_iter_item"]
