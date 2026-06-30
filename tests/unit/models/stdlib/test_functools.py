from __future__ import annotations

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.stdlib.functools.cache import (
    CachedPropertyModel,
    LRUCacheModel,
    model_cached_property,
    model_lru_cache,
)
from pysymex._internal.models.stdlib.functools.cmp import model_cmp_to_key
from pysymex._internal.models.stdlib.functools.core import (
    PartialModel,
    model_partial,
    model_reduce,
    model_singledispatch,
    model_total_ordering,
    model_wraps,
)


def _identity(value: object) -> object:
    return value


def _none_fn() -> None:
    return None


def _reduce_pick_first(a: object, b: object) -> object:
    _ = b
    return a


def _prop_value(_self: object) -> int:
    return 1


def _prop_none(_self: object) -> None:
    return None


def _cmp(a: object, b: object) -> int:
    if not isinstance(a, int) or not isinstance(b, int):
        return 0
    return a - b


class TestWrappedWrapper:
    """Test suite for pysymex._internal.models.stdlib.functools.WrappedWrapper."""

    def test_faithfulness(self) -> None:
        def wrapped() -> int:
            return 1

        def wrapper() -> int:
            return 2

        decorated = model_wraps(wrapped)(wrapper)
        assert getattr(decorated, "__name__") == wrapped.__name__

    def test_error_path(self) -> None:
        assert callable(model_wraps(_none_fn))


class TestPartialModel:
    """Test suite for pysymex._internal.models.stdlib.functools.PartialModel."""

    def test_faithfulness(self) -> None:
        partial = PartialModel(_identity, 1)
        assert partial.func is not None

    def test_error_path(self) -> None:
        partial = PartialModel(_none_fn)
        assert partial.args == ()


def test_model_partial() -> None:
    result = model_partial(_identity, 1)
    assert isinstance(result, PartialModel)


def test_model_reduce() -> None:
    lst = SymbolicList.empty("x")
    model_reduce(_reduce_pick_first, lst)


class TestLRUCacheModel:
    """Test suite for pysymex._internal.models.stdlib.functools.LRUCacheModel."""

    def test_faithfulness(self) -> None:
        model = LRUCacheModel(maxsize=32)
        assert model.maxsize == 32

    def test_error_path(self) -> None:
        model = LRUCacheModel(maxsize=None)
        assert model.maxsize is None


def test_model_lru_cache() -> None:
    assert isinstance(model_lru_cache(), LRUCacheModel)


class TestCachedPropertyModel:
    """Test suite for pysymex._internal.models.stdlib.functools.CachedPropertyModel."""

    def test_faithfulness(self) -> None:
        model = CachedPropertyModel(_prop_value)
        assert model.func is not None

    def test_error_path(self) -> None:
        model = CachedPropertyModel(_prop_none)
        assert model.__doc__ is None


def test_model_cached_property() -> None:
    result = model_cached_property(_prop_value)
    assert isinstance(result, CachedPropertyModel)


def test_model_wraps() -> None:
    def wrapped() -> int:
        return 1

    def wrapper() -> int:
        return 2

    decorated = model_wraps(wrapped)(wrapper)
    assert getattr(decorated, "__wrapped__") is wrapped


def test_model_total_ordering() -> None:
    class X:
        pass

    assert model_total_ordering(X) is X


def test_model_cmp_to_key() -> None:
    key_type = model_cmp_to_key(_cmp)
    assert key_type(1) < key_type(2)


def test_model_singledispatch() -> None:
    assert model_singledispatch(_identity) is _identity
