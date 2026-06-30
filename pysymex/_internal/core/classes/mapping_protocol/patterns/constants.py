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

"""Constant-return bytecode recognizers for modeled mapping protocol methods."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pysymex._internal.core.classes.mapping_protocol.patterns.instructions import (
    effective_instructions,
)

if TYPE_CHECKING:
    import types

NO_CONSTANT_RETURN: Final = object()


def constant_return_value(code: types.CodeType | None) -> object:
    """Return the constant for ``return <const>`` method bodies."""
    instructions = effective_instructions(code)
    if code is None:
        return NO_CONSTANT_RETURN
    if len(instructions) == 1 and instructions[0].opname == "RETURN_CONST":
        return instructions[0].argval
    if len(instructions) != 2:
        return NO_CONSTANT_RETURN
    if instructions[0].opname != "LOAD_CONST":
        return NO_CONSTANT_RETURN
    if instructions[1].opname != "RETURN_VALUE":
        return NO_CONSTANT_RETURN
    return instructions[0].argval
