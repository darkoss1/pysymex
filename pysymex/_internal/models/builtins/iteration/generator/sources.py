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

"""Shared source facts for modeled generator-expression builtin handling."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.generators import ModeledGenerator


def generator_code(generator: ModeledGenerator) -> types.CodeType | None:
    """Return the code object backing a modeled generator expression, if available."""
    function = generator.function
    code = getattr(function, "code", None)
    if isinstance(code, types.CodeType):
        return code
    code = getattr(function, "__code__", None) or getattr(function, "_func_code", None)
    return code if isinstance(code, types.CodeType) else None


def generator_items(generator: ModeledGenerator, state: VMState) -> list[object] | None:
    """Return concrete-tracked items for a modeled generator's source iterator."""
    if len(generator.args) != 1:
        return None
    iterator = generator.args[0]
    if not isinstance(iterator, SymbolicIterator):
        return None
    iterable = SymbolicObject.resolve(iterator.iterable, state)
    if isinstance(iterable, SymbolicList):
        concrete_items = iterable.concrete_items
        if concrete_items is None:
            return None
        return concrete_items[iterator.index :]
    if isinstance(iterable, (list, tuple)):
        concrete_sequence = cast("list[object] | tuple[object, ...]", iterable)
        return list(concrete_sequence[iterator.index :])
    return None
