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

"""Callee code-object signature extraction for interprocedural entry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import types


@dataclass(frozen=True, slots=True)
class CalleeSignature:
    """Argument-name slices needed for CPython-style callee binding."""

    arg_count: int
    pos_arg_names: tuple[str, ...]
    kwonly_arg_names: tuple[str, ...]


def callee_signature(func_code: types.CodeType) -> CalleeSignature:
    """Return positional and keyword-only argument names for a callee code object."""
    arg_count = func_code.co_argcount
    pos_arg_names = func_code.co_varnames[:arg_count]
    kwonly_count = func_code.co_kwonlyargcount
    kwonly_arg_names = func_code.co_varnames[arg_count : arg_count + kwonly_count]
    return CalleeSignature(
        arg_count=arg_count,
        pos_arg_names=pos_arg_names,
        kwonly_arg_names=kwonly_arg_names,
    )
