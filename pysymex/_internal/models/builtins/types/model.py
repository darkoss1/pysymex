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

"""Builtin-specific adapters for shared type-model contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.contracts.types import TypeModel, TypeModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class BuiltinTypeModel(TypeModel):
    """Model for builtin type objects like int, str, and list."""

    def __init__(self, py_type: type) -> None:
        self.name = py_type.__name__
        self.qualname = f"builtins.{py_type.__name__}"
        self.python_type = py_type

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> TypeModelResult:
        """Return the concrete builtin type represented by this adapter."""
        return TypeModelResult(value=self.python_type)
