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

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.strings import SymbolicString

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


def get_symbolic_dict(arg: object, state: VMState | None = None) -> SymbolicDict | None:
    """Extract SymbolicDict from argument, resolving SymbolicObject if needed."""
    return SymbolicDict.resolve(arg, state)


def get_symbolic_string(arg: object) -> SymbolicString | None:
    """Extract SymbolicString from argument."""
    return SymbolicString.resolve(arg)
