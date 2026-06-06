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

"""Mapping-like collections models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class OrderedDictModel:
    """Model for collections.OrderedDict."""

    @staticmethod
    def model_init(state: VMState) -> SymbolicDict:
        """Model OrderedDict() initialization."""
        return SymbolicDict.empty("ordereddict")

    @staticmethod
    def apply(
        args: list[object],
        kwargs: dict[str, object],
        state: VMState,
    ) -> object:
        """Model method calls on OrderedDict instances."""
        from pysymex.core.types.scalars.values import SymbolicValue
        from pysymex.models.builtins.base import ModelResult

        result, constraint = SymbolicValue.symbolic(f"ordereddict_call_{state.pc}_{state.path_id}")
        return ModelResult(value=result, constraints=[constraint])

    @staticmethod
    def model_move_to_end(
        _od: SymbolicDict,
        key: SymbolicValue,
        last: bool = True,
    ) -> None:
        """Model OrderedDict.move_to_end(key, last=True)."""
        _ = last
        pass

    @staticmethod
    def model_popitem(
        _od: SymbolicDict,
        last: bool = True,
    ) -> tuple[SymbolicValue, SymbolicValue]:
        """Model OrderedDict.popitem(last=True)."""
        from pysymex.core.types.scalars.values import SymbolicValue

        _ = last
        key, _ = SymbolicValue.symbolic("popitem_key")
        value, _ = SymbolicValue.symbolic("popitem_value")
        return (key, value)


class ChainMapModel:
    """Model for collections.ChainMap."""

    @staticmethod
    def model_init(
        state: VMState,
        *_maps: SymbolicDict,
    ) -> SymbolicDict:
        """Model ChainMap() initialization."""
        return SymbolicDict.empty("chainmap")

    @staticmethod
    def model_new_child(
        cm: SymbolicDict,
        m: SymbolicDict | None = None,
    ) -> SymbolicDict:
        """Model ChainMap.new_child(m=None)."""
        return SymbolicDict.empty("chainmap_child")


__all__ = ["ChainMapModel", "OrderedDictModel"]
