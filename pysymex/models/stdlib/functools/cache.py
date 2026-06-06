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

"""Cache-related functools models."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, cast


class _LRUCacheWrapper(Protocol):
    def __call__(self, *args: object, **kwargs: object) -> object: ...
    def cache_info(self) -> tuple[int, int, int | None, int]: ...
    def cache_clear(self) -> None: ...


class LRUCacheModel:
    """Model for functools.lru_cache.

    Decorator that caches function calls based on arguments.
    """

    def __init__(self, maxsize: int | None = 128, typed: bool = False) -> None:
        """Create an LRU cache.

        Args:
            maxsize: Maximum cache size (None = unlimited)
            typed: Whether to cache different types separately
        """
        self.maxsize = maxsize
        self.typed = typed
        self.cache_info_hits = 0
        self.cache_info_misses = 0

    def __call__(self, func: Callable[..., object]) -> _LRUCacheWrapper:
        """Decorate a function with caching."""

        def wrapper(*args: object, **kwargs: object) -> object:
            from pysymex.core.types.scalars.values import SymbolicValue

            result, _ = SymbolicValue.symbolic(f"lru_cached_{func.__name__}")
            return result

        setattr(
            wrapper,
            "cache_info",
            lambda: (self.cache_info_hits, self.cache_info_misses, self.maxsize, 0),
        )
        setattr(wrapper, "cache_clear", lambda: None)
        return cast("_LRUCacheWrapper", wrapper)


def model_lru_cache(
    maxsize: int | None = 128,
    typed: bool = False,
) -> LRUCacheModel:
    """Model functools.lru_cache(maxsize=128, typed=False).

    Decorator for memoization with LRU eviction.
    """
    return LRUCacheModel(maxsize, typed)


class CachedPropertyModel:
    """Model for functools.cached_property.

    Descriptor for caching method results as instance attributes.
    """

    def __init__(self, func: Callable[..., object]) -> None:
        """Create a cached property.

        Args:
            func: The method to cache
        """
        self.func: Callable[..., object] = func
        self.__doc__ = func.__doc__

    def __get__(self, obj: object, cls: type[object] | None = None) -> object:
        """Get the cached value or compute it."""
        if obj is None:
            return self

        from pysymex.core.types.scalars.values import SymbolicValue

        result, _ = SymbolicValue.symbolic(f"cached_property_{self.func.__name__}")
        return result


def model_cached_property(func: Callable[..., object]) -> CachedPropertyModel:
    """Model functools.cached_property(func).

    Converts a method to a lazy attribute.
    """
    return CachedPropertyModel(func)


__all__ = ["CachedPropertyModel", "LRUCacheModel", "model_cached_property", "model_lru_cache"]
