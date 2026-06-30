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

"""Typed wrappers for code-object process-local cache functions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Generic, NamedTuple, Protocol, TypeVar

from pysymex._internal.core.cache.control import is_process_cache_disabled

if TYPE_CHECKING:
    import types
    from collections.abc import Callable

_T = TypeVar("_T", covariant=True)
T = TypeVar("T")


class CacheInfo(NamedTuple):
    """Public cache statistics compatible with ``functools.lru_cache``."""

    hits: int
    misses: int
    maxsize: int | None
    currsize: int


class CachedCodeFunction(Protocol[_T]):
    """Callable code-object cache with ``functools.lru_cache`` controls."""

    def __call__(self, code: types.CodeType) -> _T: ...

    def cache_clear(self) -> None: ...

    def cache_info(self) -> tuple[int, int, int | None, int]: ...


class ProcessCodeCache(Generic[T]):
    """Callable wrapper that bypasses its LRU while process caches are disabled."""

    def __init__(
        self,
        cached: CachedCodeFunction[T],
        uncached: Callable[[types.CodeType], T],
    ) -> None:
        self._cached = cached
        self._uncached = uncached

    def __call__(self, code: types.CodeType) -> T:
        if is_process_cache_disabled():
            return self._uncached(code)
        return self._cached(code)

    def cache_clear(self) -> None:
        """Clear the underlying LRU cache."""
        self._cached.cache_clear()

    def cache_info(self) -> CacheInfo:
        """Return underlying LRU cache statistics."""
        hits, misses, maxsize, currsize = self._cached.cache_info()
        return CacheInfo(
            hits=int(hits),
            misses=int(misses),
            maxsize=maxsize,
            currsize=int(currsize),
        )
