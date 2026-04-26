"""Tests for pysymex.models.stdlib.functools — all model functions + classes."""

from __future__ import annotations


class TestPartialModel:
    """Test PartialModel class and model_partial factory."""

    def test_model_partial_returns_partial_model(self) -> None:
        """model_partial produces a PartialModel."""
        from pysymex.models.stdlib.functools import model_partial, PartialModel

        def dummy(a: int, b: int) -> int:
            return a + b

        result = model_partial(dummy, 1)
        assert isinstance(result, PartialModel)
        assert result.func is dummy
        assert result.args == (1,)

    def test_partial_call_returns_symbolic_value(self) -> None:
        """Calling a PartialModel produces a SymbolicValue."""
        from pysymex.models.stdlib.functools import model_partial
        from pysymex.core.types.scalars import SymbolicValue

        def dummy(a: int, b: int) -> int:
            return a + b

        partial = model_partial(dummy, 1)
        result = partial(2)
        assert isinstance(result, SymbolicValue)

    def test_partial_stores_kwargs(self) -> None:
        """PartialModel stores keyword arguments."""
        from pysymex.models.stdlib.functools import model_partial

        def dummy(a: int, b: int = 5) -> int:
            return a + b

        partial = model_partial(dummy, b=10)
        assert partial.kwargs == {"b": 10}


class TestModelReduce:
    """Test model_reduce."""

    def test_reduce_returns_symbolic(self) -> None:
        """model_reduce always returns a SymbolicValue."""
        from pysymex.models.stdlib.functools import model_reduce
        from pysymex.core.types.scalars import SymbolicValue
        from pysymex.core.types.containers import SymbolicList

        def add(a: object, b: object) -> object:
            return a

        iterable = SymbolicList.empty("test_list")
        result = model_reduce(add, iterable)
        assert isinstance(result, SymbolicValue)


class TestLRUCacheModel:
    """Test LRUCacheModel class and model_lru_cache factory."""

    def test_model_lru_cache_returns_model(self) -> None:
        """model_lru_cache returns LRUCacheModel."""
        from pysymex.models.stdlib.functools import model_lru_cache, LRUCacheModel

        model = model_lru_cache(maxsize=64, typed=True)
        assert isinstance(model, LRUCacheModel)
        assert model.maxsize == 64

    def test_wrapped_function_returns_symbolic(self) -> None:
        """Calling a wrapped function returns SymbolicValue."""
        from pysymex.models.stdlib.functools import LRUCacheModel
        from pysymex.core.types.scalars import SymbolicValue

        def my_func(x: int) -> int:
            return x * 2

        cache = LRUCacheModel()
        wrapper = cache(my_func)
        result = wrapper(42)
        assert isinstance(result, SymbolicValue)

    def test_cache_info_returns_tuple(self) -> None:
        """cache_info() returns (hits, misses, maxsize, size) tuple."""
        from pysymex.models.stdlib.functools import LRUCacheModel

        cache = LRUCacheModel(maxsize=256)
        wrapper = cache(lambda x: x)
        info = wrapper.cache_info()
        assert info == (0, 0, 256, 0)


class TestCachedPropertyModel:
    """Test CachedPropertyModel class and model_cached_property factory."""

    def test_get_with_none_returns_descriptor(self) -> None:
        """__get__ with obj=None returns the descriptor itself."""
        from pysymex.models.stdlib.functools import CachedPropertyModel

        def prop(self: object) -> int:
            return 42

        descriptor = CachedPropertyModel(prop)
        result = descriptor.__get__(None, type)
        assert result is descriptor

    def test_get_with_instance_returns_symbolic(self) -> None:
        """__get__ with a real object returns SymbolicValue."""
        from pysymex.models.stdlib.functools import CachedPropertyModel
        from pysymex.core.types.scalars import SymbolicValue

        def prop(self: object) -> int:
            return 42

        descriptor = CachedPropertyModel(prop)
        result = descriptor.__get__(object(), type)
        assert isinstance(result, SymbolicValue)


class TestModelWraps:
    """Test model_wraps."""

    def test_wraps_preserves_name(self) -> None:
        """model_wraps copies __name__ from wrapped to wrapper."""
        from pysymex.models.stdlib.functools import model_wraps

        def real_func() -> None:
            """Real docstring."""
            return None

        @model_wraps(real_func)
        def wrapper() -> None:
            return None

        assert wrapper.__name__ == "real_func"


class TestModelCmpToKey:
    """Test model_cmp_to_key."""

    def test_returns_key_class(self) -> None:
        """model_cmp_to_key returns a class with comparison methods."""
        from pysymex.models.stdlib.functools import model_cmp_to_key

        def cmp(a: object, b: object) -> int:
            if a == b:
                return 0
            return -1 if a < b else 1  # type: ignore[operator]

        K = model_cmp_to_key(cmp)
        k1 = K(1)
        k2 = K(2)
        assert k1 < k2
        assert k2 > k1
        assert k1 == K(1)

    def test_eq_with_non_k_returns_not_implemented(self) -> None:
        """K.__eq__ with non-K object returns NotImplemented."""
        from pysymex.models.stdlib.functools import model_cmp_to_key

        def cmp(a: object, b: object) -> int:
            return 0

        K = model_cmp_to_key(cmp)
        k = K(1)
        result = k.__eq__("not_a_k")
        assert result is NotImplemented


class TestModelTotalOrdering:
    """Test model_total_ordering."""

    def test_returns_class_unchanged(self) -> None:
        """model_total_ordering returns the class as-is."""
        from pysymex.models.stdlib.functools import model_total_ordering

        class MyClass:
            pass

        result = model_total_ordering(MyClass)
        assert result is MyClass


class TestModelSingledispatch:
    """Test model_singledispatch."""

    def test_returns_function_unchanged(self) -> None:
        """model_singledispatch returns the function as-is."""
        from pysymex.models.stdlib.functools import model_singledispatch

        def my_func(x: int) -> str:
            return str(x)

        assert model_singledispatch(my_func) is my_func


class TestGetFunctoolsModel:
    """Test get_functools_model."""

    def test_known_returns_model(self) -> None:
        """Known name returns the correct model."""
        from pysymex.models.stdlib.functools import get_functools_model, model_partial

        assert get_functools_model("partial") is model_partial

    def test_unknown_returns_none(self) -> None:
        """Unknown name returns None."""
        from pysymex.models.stdlib.functools import get_functools_model

        assert get_functools_model("nonexistent") is None


class TestRegisterFunctoolsModels:
    """Test register_functools_models."""

    def test_returns_full_qualified_mapping(self) -> None:
        """All models returned with 'functools.' prefix."""
        from pysymex.models.stdlib.functools import register_functools_models

        registry = register_functools_models()
        assert "functools.partial" in registry
        assert "functools.reduce" in registry
        assert len(registry) == 8
