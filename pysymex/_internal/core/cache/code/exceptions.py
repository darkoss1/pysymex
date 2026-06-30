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

"""Exception-table metadata cache for code objects."""

from __future__ import annotations

import dis
import functools
from typing import TYPE_CHECKING

from pysymex._internal.core.cache.code.wrappers import ProcessCodeCache
from pysymex._internal.core.cache.control import register_process_cache_clearer

if TYPE_CHECKING:
    import types


@functools.lru_cache(maxsize=2048)
def _cached_get_exception_entries(code: types.CodeType) -> tuple[object, ...]:
    """Return cached CPython exception-table entries for ``code``."""
    return _uncached_get_exception_entries(code)


def _uncached_get_exception_entries(code: types.CodeType) -> tuple[object, ...]:
    """Return CPython exception-table entries without consulting the process LRU."""
    try:
        return tuple(getattr(dis.Bytecode(code), "exception_entries", ()))
    except (AttributeError, TypeError):
        return ()


get_exception_entries = ProcessCodeCache(
    _cached_get_exception_entries,
    _uncached_get_exception_entries,
)
"""Return CPython exception-table entries for ``code``.

Entries normally use the same process-wide code-object cache policy as
instruction tuples. Fresh-run cache-disabled contexts bypass the LRU.
"""


register_process_cache_clearer("core.code.exception_entries", get_exception_entries.cache_clear)
