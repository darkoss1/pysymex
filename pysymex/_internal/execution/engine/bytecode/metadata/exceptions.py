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

"""Exception-table metadata selection for bytecode execution."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

from pysymex._internal.core.cache.code.exceptions import get_exception_entries

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import CodeType

ExceptionEntries = tuple[object, ...]


def exception_entries_for_execution(
    bytecode_source: Callable[..., object] | CodeType,
    code: CodeType,
) -> ExceptionEntries:
    """Return exception entries for the execution source/code pairing."""
    if bytecode_source_matches_code(bytecode_source, code):
        return get_exception_entries(code)
    return exception_entries_from_source(bytecode_source)


def bytecode_source_matches_code(
    bytecode_source: Callable[..., object] | CodeType,
    code: CodeType,
) -> bool:
    """Return true when a bytecode source is represented by ``code``."""
    if bytecode_source is code:
        return True
    return getattr(bytecode_source, "__code__", None) is code


def exception_entries_from_source(
    bytecode_source: Callable[..., object] | CodeType,
) -> ExceptionEntries:
    """Return exception entries for a non-standard bytecode source."""
    try:
        bytecode_obj = dis.Bytecode(bytecode_source)
        entries = getattr(bytecode_obj, "exception_entries", ())
        return tuple(entries)
    except (AttributeError, TypeError):
        return ()
