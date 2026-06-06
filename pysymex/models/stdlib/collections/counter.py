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

"""Counter model for collections."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class CounterModel:
    """Model for collections.Counter.

    Counter is a dict subclass for counting hashable objects.
    Elements are stored as dictionary keys and counts as values.
    """

    @staticmethod
    def model_init(
        state: VMState,
        iterable: SymbolicList | None = None,
    ) -> SymbolicDict:
        """Model Counter() initialization."""
        counter = SymbolicDict.empty("counter")
        return counter

    @staticmethod
    def model_most_common(
        counter: SymbolicDict,
        n: SymbolicValue | int | None = None,
    ) -> SymbolicList:
        """Model Counter.most_common(n)."""
        result = SymbolicList.empty("most_common_result")
        return result

    @staticmethod
    def model_elements(counter: SymbolicDict) -> SymbolicList:
        """Model Counter.elements()."""
        return SymbolicList.empty("counter_elements")

    @staticmethod
    def model_subtract(
        counter: SymbolicDict,
        other: SymbolicDict | None = None,
    ) -> None:
        """Model Counter.subtract()."""
        pass

    @staticmethod
    def model_update(
        counter: SymbolicDict,
        other: SymbolicDict | None = None,
    ) -> None:
        """Model Counter.update()."""
        pass


__all__ = ["CounterModel"]
