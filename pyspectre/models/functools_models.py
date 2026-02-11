"""Models for the functools module.

This module provides symbolic models for functools functions:
- partial
- reduce
- lru_cache
- cached_property
- wraps
- total_ordering

v0.3.0-alpha: Initial implementation
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

import z3

if TYPE_CHECKING:
    from pyspectre.core.types import SymbolicValue

from pyspectre.core.types import SymbolicList


class PartialModel:
    """Model for functools.partial.

    Freezes some arguments of a function.
    """

    def __init__(self, func: Callable, *args, **kwargs):
        """Create a partial function application.

        Args:
            func: The function to partially apply
            *args: Positional arguments to freeze
            **kwargs: Keyword arguments to freeze
        """
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def __call__(self, *args, **kwargs) -> Any:
        """Call the partial function with remaining arguments."""
        all_args = self.args + args
        all_kwargs = {**self.kwargs, **kwargs}

        from pyspectre.core.types import SymbolicValue

        result, _ = SymbolicValue.symbolic("partial_result")
        return result


def model_partial(func: Callable, *args, **kwargs) -> PartialModel:
    """Model functools.partial(func, *args, **kwargs).

    Returns a new callable with some arguments pre-filled.
    """
    return PartialModel(func, *args, **kwargs)


def model_reduce(
    function: Callable,
    iterable: SymbolicList,
    initial: Any = None,
) -> Any:
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
    from pyspectre.core.types import SymbolicValue

    result, _ = SymbolicValue.symbolic("reduce_result")
    return result


class LRUCacheModel:
    """Model for functools.lru_cache.

    Decorator that caches function calls based on arguments.
    """

    def __init__(self, maxsize: int | None = 128, typed: bool = False):
        """Create an LRU cache.

        Args:
            maxsize: Maximum cache size (None = unlimited)
            typed: Whether to cache different types separately
        """
        self.maxsize = maxsize
        self.typed = typed
        self.cache_info_hits = 0
        self.cache_info_misses = 0

    def __call__(self, func: Callable) -> Callable:
        """Decorate a function with caching."""

        def wrapper(*args, **kwargs):
            from pyspectre.core.types import SymbolicValue

            result, _ = SymbolicValue.symbolic(f"lru_cached_{func.__name__}")
            return result

        wrapper.cache_info = lambda: (
            self.cache_info_hits,
            self.cache_info_misses,
            self.maxsize,
            0,
        )
        wrapper.cache_clear = lambda: None
        return wrapper


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

    def __init__(self, func: Callable):
        """Create a cached property.

        Args:
            func: The method to cache
        """
        self.func = func
        self.__doc__ = func.__doc__

    def __get__(self, obj, cls=None):
        """Get the cached value or compute it."""
        if obj is None:
            return self

        from pyspectre.core.types import SymbolicValue

        result, _ = SymbolicValue.symbolic(f"cached_property_{self.func.__name__}")
        return result


def model_cached_property(func: Callable) -> CachedPropertyModel:
    """Model functools.cached_property(func).

    Converts a method to a lazy attribute.
    """
    return CachedPropertyModel(func)


def model_wraps(wrapped: Callable, **kwargs) -> Callable:
    """Model functools.wraps(wrapped, **kwargs).

    Decorator to make wrapper functions look like wrapped functions.
    """

    def decorator(wrapper: Callable) -> Callable:
        wrapper.__name__ = getattr(wrapped, "__name__", wrapper.__name__)
        wrapper.__doc__ = getattr(wrapped, "__doc__", wrapper.__doc__)
        wrapper.__wrapped__ = wrapped
        return wrapper

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


def model_cmp_to_key(mycmp: Callable) -> type:
    """Model functools.cmp_to_key(mycmp).

    Converts an old-style comparison function to a key function.
    """

    class K:
        __slots__ = ["obj"]

        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

    return K


def model_singledispatch(func: Callable) -> Callable:
    """Model functools.singledispatch(func).

    Single-dispatch generic function decorator.
    """
    return func


FUNCTOOLS_MODELS = {
    "partial": model_partial,
    "reduce": model_reduce,
    "lru_cache": model_lru_cache,
    "cached_property": model_cached_property,
    "wraps": model_wraps,
    "total_ordering": model_total_ordering,
    "cmp_to_key": model_cmp_to_key,
    "singledispatch": model_singledispatch,
}


def get_functools_model(name: str) -> Callable | None:
    """Get the model for a functools function.

    Args:
        name: Name of the functools function

    Returns:
        The model or None if not found
    """
    return FUNCTOOLS_MODELS.get(name)


def register_functools_models() -> dict[str, Callable]:
    """Register all functools models.

    Returns:
        Dict mapping fully qualified names to models
    """
    return {f"functools.{name}": model for name, model in FUNCTOOLS_MODELS.items()}
