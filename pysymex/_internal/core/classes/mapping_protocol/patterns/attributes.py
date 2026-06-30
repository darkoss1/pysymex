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

"""Backing-attribute bytecode recognizers for mapping protocol methods."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.classes.mapping_protocol.patterns.instructions import (
    effective_instructions,
    loads_local,
)

if TYPE_CHECKING:
    import types


def keys_method_backing_attr(code: types.CodeType | None) -> str | None:
    """Match ``return self.<attr>.keys()`` and return ``<attr>``."""
    instructions = effective_instructions(code)
    if code is None or len(instructions) != 5:
        return None
    if not loads_local(instructions[0], code, 0):
        return None
    if instructions[1].opname != "LOAD_ATTR" or not isinstance(instructions[1].argval, str):
        return None
    if (
        instructions[2].opname not in {"LOAD_ATTR", "LOAD_METHOD"}
        or instructions[2].argval != "keys"
    ):
        return None
    if instructions[3].opname != "CALL" or instructions[3].arg not in {0, None}:
        return None
    if instructions[4].opname != "RETURN_VALUE":
        return None
    return instructions[1].argval


def getitem_method_backing_attr(code: types.CodeType | None) -> str | None:
    """Match ``return self.<attr>[key]`` and return ``<attr>``."""
    instructions = effective_instructions(code)
    if code is None or len(instructions) != 5:
        return None
    if not loads_local(instructions[0], code, 0):
        return None
    if instructions[1].opname != "LOAD_ATTR" or not isinstance(instructions[1].argval, str):
        return None
    if not loads_local(instructions[2], code, 1):
        return None
    if instructions[3].opname != "BINARY_SUBSCR":
        return None
    if instructions[4].opname != "RETURN_VALUE":
        return None
    return instructions[1].argval
