from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from pysymex.core.types.containers import SymbolicList


def _load_functools_models() -> ModuleType:
    module_path = (
        Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "functools.py"
    )
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_functools", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib functools models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


functools_models = _load_functools_models()


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


def _cmp(a: int, b: int) -> int:
    return a - b


class TestWrappedWrapper:
    """Test suite for pysymex.models.stdlib.functools.WrappedWrapper."""

    def test_faithfulness(self) -> None:
        def wrapped() -> int:
            return 1

        def wrapper() -> int:
            return 2

        decorated = functools_models.model_wraps(wrapped)(wrapper)
        assert decorated.__name__ == wrapped.__name__

    def test_error_path(self) -> None:
        assert callable(functools_models.model_wraps(_none_fn))


class TestPartialModel:
    """Test suite for pysymex.models.stdlib.functools.PartialModel."""

    def test_faithfulness(self) -> None:
        partial = functools_models.PartialModel(_identity, 1)
        assert partial.func is not None

    def test_error_path(self) -> None:
        partial = functools_models.PartialModel(_none_fn)
        assert partial.args == ()


def test_model_partial() -> None:
    result = functools_models.model_partial(_identity, 1)
    assert isinstance(result, functools_models.PartialModel)


def test_model_reduce() -> None:
    lst = SymbolicList.empty("x")
    functools_models.model_reduce(_reduce_pick_first, lst)


class TestLRUCacheModel:
    """Test suite for pysymex.models.stdlib.functools.LRUCacheModel."""

    def test_faithfulness(self) -> None:
        model = functools_models.LRUCacheModel(maxsize=32)
        assert model.maxsize == 32

    def test_error_path(self) -> None:
        model = functools_models.LRUCacheModel(maxsize=None)
        assert model.maxsize is None


def test_model_lru_cache() -> None:
    assert isinstance(functools_models.model_lru_cache(), functools_models.LRUCacheModel)


class TestCachedPropertyModel:
    """Test suite for pysymex.models.stdlib.functools.CachedPropertyModel."""

    def test_faithfulness(self) -> None:
        model = functools_models.CachedPropertyModel(_prop_value)
        assert model.func is not None

    def test_error_path(self) -> None:
        model = functools_models.CachedPropertyModel(_prop_none)
        assert model.__doc__ is None


def test_model_cached_property() -> None:
    result = functools_models.model_cached_property(_prop_value)
    assert isinstance(result, functools_models.CachedPropertyModel)


def test_model_wraps() -> None:
    def wrapped() -> int:
        return 1

    def wrapper() -> int:
        return 2

    decorated = functools_models.model_wraps(wrapped)(wrapper)
    assert decorated.__wrapped__ is wrapped


def test_model_total_ordering() -> None:
    class X:
        pass

    assert functools_models.model_total_ordering(X) is X


def test_model_cmp_to_key() -> None:
    key_type = functools_models.model_cmp_to_key(_cmp)
    assert key_type(1) < key_type(2)


def test_model_singledispatch() -> None:
    assert functools_models.model_singledispatch(_identity) is _identity


def test_get_functools_model() -> None:
    assert callable(functools_models.get_functools_model("partial"))
    assert functools_models.get_functools_model("missing") is None


def test_register_functools_models() -> None:
    registered = functools_models.register_functools_models()
    assert "functools.partial" in registered
