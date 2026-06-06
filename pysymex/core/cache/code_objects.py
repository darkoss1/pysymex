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

"""Process-wide LRU cache for instruction tuples keyed by code objects."""

from __future__ import annotations

import dis
import functools
import types
from collections.abc import Callable
from typing import Generic, NamedTuple, Protocol, TypeVar, cast

from pysymex.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)

_T = TypeVar("_T", covariant=True)


class CacheInfo(NamedTuple):
    """Public cache statistics compatible with ``functools.lru_cache``."""

    hits: int
    misses: int
    maxsize: int | None
    currsize: int


class _CachedCodeFunction(Protocol[_T]):
    """Callable code-object cache with ``functools.lru_cache`` controls."""

    def __call__(self, code: types.CodeType) -> _T: ...

    def cache_clear(self) -> None: ...

    def cache_info(self) -> object: ...


class _ProcessCodeCache(Generic[_T]):
    """Callable wrapper that bypasses its LRU while process caches are disabled."""

    def __init__(
        self,
        cached: _CachedCodeFunction[_T],
        uncached: Callable[[types.CodeType], _T],
    ) -> None:
        self._cached = cached
        self._uncached = uncached

    def __call__(self, code: types.CodeType) -> _T:
        if is_process_cache_disabled():
            return self._uncached(code)
        return self._cached(code)

    def cache_clear(self) -> None:
        """Clear the underlying LRU cache."""
        self._cached.cache_clear()

    def cache_info(self) -> CacheInfo:
        """Return underlying LRU cache statistics."""
        info = self._cached.cache_info()
        return CacheInfo(
            hits=int(getattr(info, "hits")),
            misses=int(getattr(info, "misses")),
            maxsize=getattr(info, "maxsize"),
            currsize=int(getattr(info, "currsize")),
        )


@functools.lru_cache(maxsize=2048)
def _cached_get_instructions(code: types.CodeType) -> tuple[dis.Instruction, ...]:
    """Return a cached immutable instruction tuple for ``code``."""
    return _uncached_get_instructions(code)


def _uncached_get_instructions(code: types.CodeType) -> tuple[dis.Instruction, ...]:
    """Return immutable instructions without consulting the process LRU."""
    return tuple(
        _normalize_instruction(code, instruction) for instruction in dis.get_instructions(code)
    )


def _normalize_instruction(
    code: types.CodeType,
    instruction: dis.Instruction,
) -> dis.Instruction:
    """Patch CPython-version metadata gaps in disassembled instructions."""
    if instruction.opname != "KW_NAMES" or not isinstance(instruction.arg, int):
        return instruction
    try:
        kw_names = code.co_consts[instruction.arg]
    except IndexError:
        return instruction
    if not isinstance(kw_names, tuple):
        return instruction
    kw_names_tuple = cast("tuple[object, ...]", kw_names)
    return instruction._replace(argval=kw_names_tuple, argrepr=repr(kw_names_tuple))


get_instructions = _ProcessCodeCache(_cached_get_instructions, _uncached_get_instructions)
"""Return immutable instructions for ``code``.

Entries normally use a process-wide LRU cache keyed by the code object. While
``pysymex.core.cache.control.process_caches_disabled`` is active, calls bypass
that LRU and do not store entries.
"""


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


get_exception_entries = _ProcessCodeCache(
    _cached_get_exception_entries,
    _uncached_get_exception_entries,
)
"""Return CPython exception-table entries for ``code``.

Entries normally use the same process-wide code-object cache policy as
instruction tuples. Fresh-run cache-disabled contexts bypass the LRU.
"""


def _clear_code_object_caches() -> None:
    """Clear process-local code-object instruction metadata caches."""
    get_instructions.cache_clear()
    get_exception_entries.cache_clear()


register_process_cache_clearer("core.code_object_caches", _clear_code_object_caches)


__all__ = ["CacheInfo", "get_exception_entries", "get_instructions"]
