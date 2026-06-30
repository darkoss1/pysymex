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

"""Literal-yield inspection for simple finite modeled generators."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex._internal.core.calls.payload import function_payload

if TYPE_CHECKING:
    from pysymex._internal.core.types.containers.generators import ModeledGenerator


def literal_generator_yields(generator: ModeledGenerator) -> tuple[object, ...] | None:
    """Return literal yield values for simple finite generators, if fully known."""
    payload = function_payload(generator.function)
    code = payload.code if payload is not None else getattr(generator.function, "__code__", None)
    if code is None:
        return None
    instructions = list(dis.get_instructions(code))
    values: list[object] = []
    for index, instruction in enumerate(instructions):
        if instruction.opname != "YIELD_VALUE":
            continue
        if index == 0 or instructions[index - 1].opname != "LOAD_CONST":
            return None
        values.append(instructions[index - 1].argval)
    return tuple(values) if values else None
