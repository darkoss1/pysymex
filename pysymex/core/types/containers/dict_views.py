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

"""Live dictionary view carriers for modeled ``dict.keys``/``values``/``items``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import z3

from pysymex.core.types.base import SymbolicType
from pysymex.core.types.containers.dicts import SymbolicDict

DictViewKind = Literal["keys", "values", "items"]


@dataclass(frozen=True, slots=True)
class SymbolicDictView(SymbolicType):
    """Live view over a modeled dictionary source.

    CPython dictionary views reflect later mutations to the underlying dict.
    This carrier stores the current modeled dict source and is replaced when
    mutation side effects replace that source in the VM state.
    """

    _name: str
    source: SymbolicDict
    kind: DictViewKind

    __hash__ = object.__hash__

    @property
    def name(self) -> str:
        """Return the diagnostic name."""
        return self._name

    def to_z3(self) -> z3.ExprRef:
        """Use the source length as the view's symbolic representative."""
        return self.source.z3_len

    def hash_value(self) -> int:
        """Return a structural hash for duplicate-state bookkeeping."""
        return (self.source.hash_value() * 31) ^ hash(self.kind)

    def could_be_truthy(self) -> z3.BoolRef:
        """Return whether the current source dict can be nonempty."""
        return self.source.could_be_truthy()

    def could_be_falsy(self) -> z3.BoolRef:
        """Return whether the current source dict can be empty."""
        return self.source.could_be_falsy()

    def with_source(self, source: SymbolicDict) -> SymbolicDictView:
        """Return this view retargeted to an updated modeled dict source."""
        return SymbolicDictView(self._name, source, self.kind)

    @property
    def concrete_items(self) -> list[object] | None:
        """Return exact current view items when the source dict is exact."""
        concrete = self.source.concrete_items
        if concrete is None:
            return None
        if self.kind == "keys":
            return list(concrete.keys())
        if self.kind == "values":
            return list(concrete.values())
        return list(concrete.items())


__all__ = ["DictViewKind", "SymbolicDictView"]
