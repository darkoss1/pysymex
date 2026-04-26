# pysymex: Python Symbolic Execution & Formal Verification
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

"""Models for the functools module.

This module provides symbolic models for functools functions:
- partial
- reduce
- lru_cache
- cached_property
- wraps
- total_ordering

"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, cast

from pysymex.core.types.scalars import SymbolicList


class _LRUCacheWrapper(Protocol):
    def __call__(self, *args: object, **kwargs: object) -> object: ...
    def cache_info(self) -> tuple[int, int, int | None, int]: ...
    def cache_clear(self) -> None: ...


class WrappedWrapper(Protocol):
    __name__: str
    __doc__: str | None
    __wrapped__: Callable[..., object]

    def __call__(self, *args: object, **kwargs: object) -> object: ...


class PartialModel:
    """Model for functools.partial.

    Freezes some arguments of a function.
    """

    def __init__(self, func: Callable[..., object], *args: object, **kwargs: object) -> None:
        """Create a partial function application.

        Args:
            func: The function to partially apply
            *args: Positional arguments to freeze
            **kwargs: Keyword arguments to freeze
        """
        self.func: Callable[..., object] = func
        self.args: tuple[object, ...] = args
        self.kwargs: dict[str, object] = kwargs

    def __call__(self, *args: object, **kwargs: object) -> object:
        """Call the partial function with remaining arguments."""
        _ = self.args + args

        from pysymex.core.types.scalars import SymbolicValue

        result, _ = SymbolicValue.symbolic("partial_result")
        return result


def model_partial(func: Callable[..., object], *args: object, **kwargs: object) -> PartialModel:
    """Model functools.partial(func, *args, **kwargs).

    Returns a new callable with some arguments pre-filled.
    """
    return PartialModel(func, *args, **kwargs)


def model_reduce(
    function: Callable[..., object],
    iterable: SymbolicList,
    initial: object = None,
) -> object:
    """Model functools.reduce(function, iterable[, initial]).

    Apply function of two arguments cumulatively to items of iterable.

    Args:
        function: Binary function (takes 2 args, returns 1)
        iterable: Iterable to reduce
        initial: Optional initial value

    Returns:
        The reduced value (symbolic)

    Raises:
        TypeError: If iterable is empty and no initial value
    """
    from pysymex.core.types.scalars import SymbolicValue

    result, _ = SymbolicValue.symbolic("reduce_result")
    return result


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
            from pysymex.core.types.scalars import SymbolicValue

            result, _ = SymbolicValue.symbolic(f"lru_cached_{func.__name__}")
            return result

        wrapper.cache_info = lambda: (self.cache_info_hits, self.cache_info_misses, self.maxsize, 0)  # type: ignore[reportFunctionMemberAccess]  # lru_cache adds cache_info attribute
        wrapper.cache_clear = lambda: None  # type: ignore[reportFunctionMemberAccess]  # lru_cache adds cache_clear attribute
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

        from pysymex.core.types.scalars import SymbolicValue

        result, _ = SymbolicValue.symbolic(f"cached_property_{self.func.__name__}")
        return result


def model_cached_property(func: Callable[..., object]) -> CachedPropertyModel:
    """Model functools.cached_property(func).

    Converts a method to a lazy attribute.
    """
    return CachedPropertyModel(func)


def model_wraps(wrapped: Callable[..., object], **kwargs: object) -> Callable[..., object]:
    """Model functools.wraps(wrapped, **kwargs).

    Decorator to make wrapper functions look like wrapped functions.
    """

    def decorator(wrapper: Callable[..., object]) -> Callable[..., object]:
        wrapped_wrapper = cast("WrappedWrapper", wrapper)
        wrapped_wrapper.__name__ = getattr(wrapped, "__name__", wrapped_wrapper.__name__)
        wrapped_wrapper.__doc__ = getattr(wrapped, "__doc__", wrapped_wrapper.__doc__)
        wrapped_wrapper.__wrapped__ = wrapped
        return wrapped_wrapper

    return decorator


def model_total_ordering(cls: type) -> type:
    """Model functools.total_ordering(cls).

    Decorator that fills in comparison methods.
    Given __eq__ and one of __lt__, __le__, __gt__, __ge__,
    this fills in the rest.

    Args:
        cls: Class to decorate

    Returns:
        The decorated class
    """
    return cls


def model_cmp_to_key(mycmp: Callable[[object, object], object]) -> type:
    """Model functools.cmp_to_key(mycmp).

    Converts an old-style comparison function to a key function.
    """

    def _cmp_as_int(res: object) -> int:
        if isinstance(res, bool):
            return int(res)
        if isinstance(res, int):
            return res
        int_method = getattr(res, "__int__", None)
        if callable(int_method):
            try:
                int_value = int_method()
                if isinstance(int_value, int):
                    return int_value
                return 0
            except (TypeError, ValueError):
                return 0
        return 0

    class K:
        """Key selector wrapper for comparison functions."""

        __slots__ = ["obj"]

        def __init__(self, obj: object) -> None:
            """Initialize a new K instance."""
            self.obj = obj

        def __lt__(self, other: K) -> bool:
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) < 0

        def __gt__(self, other: K) -> bool:
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) > 0

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, K):
                return NotImplemented
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) == 0

        def __le__(self, other: K) -> bool:
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) <= 0

        def __ge__(self, other: K) -> bool:
            res = mycmp(self.obj, other.obj)
            return _cmp_as_int(res) >= 0

    return K


def model_singledispatch(func: Callable[..., object]) -> Callable[..., object]:
    """Model functools.singledispatch(func).

    Single-dispatch generic function decorator.
    """
    return func


FUNCTOOLS_MODELS: dict[str, Callable[..., object]] = {
    "partial": model_partial,
    "reduce": model_reduce,
    "lru_cache": model_lru_cache,
    "cached_property": model_cached_property,
    "wraps": model_wraps,
    "total_ordering": model_total_ordering,
    "cmp_to_key": model_cmp_to_key,
    "singledispatch": model_singledispatch,
}


def get_functools_model(name: str) -> Callable[..., object] | None:
    """Get the model for a functools function.

    Args:
        name: Name of the functools function

    Returns:
        The model or None if not found
    """
    return FUNCTOOLS_MODELS.get(name)


def register_functools_models() -> dict[str, Callable[..., object]]:
    """Register all functools models.

    Returns:
        Dict mapping fully qualified names to models
    """
    return {f"functools.{name}": model for name, model in FUNCTOOLS_MODELS.items()}
