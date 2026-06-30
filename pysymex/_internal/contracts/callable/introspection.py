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

"""Predicate bytecode, global, and closure inspection for callable safety."""

from __future__ import annotations

import dis
from functools import lru_cache
from types import CodeType
from typing import TYPE_CHECKING

from pysymex._internal.contracts.callable.markers import UnknownValue

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


@lru_cache(maxsize=2048)
def code_instructions(code: CodeType) -> tuple[dis.Instruction, ...]:
    """Return decoded bytecode instructions for a code object."""
    return tuple(dis.get_instructions(code))


def global_value(globals_map: Mapping[str, object], name: str) -> object:
    """Return a global value without executing attribute lookup or other code."""
    return globals_map.get(name, UnknownValue)


def closure_values(predicate: Callable[..., object], code: CodeType) -> dict[str, object]:
    """Return closure cell values keyed by free variable name."""
    closure = getattr(predicate, "__closure__", None)
    if closure is None:
        return {}
    values: dict[str, object] = {}
    for name, cell in zip(code.co_freevars, closure, strict=False):
        try:
            values[name] = cell.cell_contents
        except ValueError:
            values[name] = UnknownValue
    return values


def predicate_code(predicate: Callable[..., object]) -> CodeType | None:
    """Return Python bytecode for a function, bound method, or callable object."""
    code = getattr(predicate, "__code__", None)
    if isinstance(code, CodeType):
        return code

    call_method = getattr(predicate, "__call__", None)
    call_code = getattr(call_method, "__code__", None)
    if isinstance(call_code, CodeType):
        return call_code
    return None
