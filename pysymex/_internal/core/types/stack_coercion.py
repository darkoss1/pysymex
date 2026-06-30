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

"""Coerce runtime and symbolic values into the VM stack-value domain."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


class StackValuePolicy:
    """Normalize runtime and symbolic carriers into VM stack shapes."""

    @staticmethod
    def coerce(value: object) -> StackValue:
        """Coerce runtime or symbolic values into the VM ``StackValue`` domain."""
        if value is None:
            return None
        if isinstance(
            value,
            (
                SymbolicValue,
                SymbolicNoneType,
                SymbolicString,
                SymbolicList,
                SymbolicDict,
                SymbolicObject,
                SymbolicTuple,
                int,
                bool,
                str,
                float,
                bytes,
                type,
                list,
                dict,
                tuple,
            ),
        ):
            return cast("StackValue", value)
        return SymbolicValue.from_const(value)

    @staticmethod
    def as_symbolic(value: StackValue) -> SymbolicValue:
        """Wrap stack values as :class:`~pysymex._internal.core.types.scalars.values.SymbolicValue`."""
        if isinstance(value, SymbolicValue):
            return value
        if hasattr(value, "type_tag"):
            return SymbolicValue.from_specialized(value)
        return SymbolicValue.from_const(value)

    @staticmethod
    def as_index(value: StackValue) -> SymbolicValue | None:
        """Return an index-shaped symbolic value when coercion is supported."""
        if isinstance(value, SymbolicValue):
            return value
        if isinstance(value, (int, bool)):
            return SymbolicValue.from_const(int(value))
        return None

    @staticmethod
    def as_dict_key(value: StackValue) -> SymbolicString | None:
        """Return a dict-key-shaped :class:`~pysymex._internal.core.types.scalars.strings.SymbolicString`."""
        if isinstance(value, SymbolicString):
            return value
        if isinstance(value, str):
            return SymbolicString.from_const(value)
        if isinstance(value, SymbolicValue):
            return SymbolicString(_name=value.name, _unified=value)
        return None
