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

"""Tuple container model operations."""

from __future__ import annotations

import dataclasses
from typing import cast

from pysymex._internal.core.types.containers.lists import SymbolicList


class TupleContainerOps:
    """Domain owner for symbolic tuple extraction from stack values."""

    @staticmethod
    def get_symbolic_tuple(arg: object) -> SymbolicList | None:
        """Extract SymbolicList (used for tuples) from argument."""
        if isinstance(arg, SymbolicList):
            return arg
        if isinstance(arg, tuple):
            values = cast("tuple[object, ...]", arg)
            return dataclasses.replace(SymbolicList.from_const(values), _type="tuple")
        return getattr(arg, "_symbolic_list", None) if arg is not None else None
