"""Tests for stdlib models (collections, itertools, functools).

These tests verify that the symbolic models are correctly structured
and can be used in symbolic execution.
"""

import pytest


from pysymex.models.collections_models import (
    COLLECTIONS_MODELS,
    ChainMapModel,
    CounterModel,
    DefaultDictModel,
    DequeModel,
    OrderedDictModel,
    get_collections_model,
    register_collections_models,
)

from pysymex.models.functools_models import (
    FUNCTOOLS_MODELS,
    LRUCacheModel,
    PartialModel,
    get_functools_model,
    model_partial,
    model_reduce,
    register_functools_models,
)

from pysymex.models.itertools_models import (
    ITERTOOLS_MODELS,
    get_itertools_model,
    model_chain,
    model_islice,
    model_product,
    model_repeat,
    model_zip_longest,
    register_itertools_models,
)


class TestCollectionsModels:
    """Test collections module models."""

    def test_all_models_registered(self):
        """All expected models should be registered."""

        expected = ["Counter", "defaultdict", "deque", "OrderedDict", "ChainMap"]

        for name in expected:
            assert name in COLLECTIONS_MODELS, f"Missing model: {name}"

    def test_get_counter_model(self):
        """Should retrieve Counter model."""

        model = get_collections_model("Counter")

        assert model is CounterModel

    def test_get_defaultdict_model(self):
        """Should retrieve defaultdict model."""

        model = get_collections_model("defaultdict")

        assert model is DefaultDictModel

    def test_get_deque_model(self):
        """Should retrieve deque model."""

        model = get_collections_model("deque")

        assert model is DequeModel

    def test_get_ordereddict_model(self):
        """Should retrieve OrderedDict model."""

        model = get_collections_model("OrderedDict")

        assert model is OrderedDictModel

    def test_get_chainmap_model(self):
        """Should retrieve ChainMap model."""

        model = get_collections_model("ChainMap")

        assert model is ChainMapModel

    def test_get_unknown_returns_none(self):
        """Unknown model should return None."""

        assert get_collections_model("UnknownType") is None

    def test_register_creates_qualified_names(self):
        """Registration should create fully qualified names."""

        registered = register_collections_models()

        assert "collections.Counter" in registered

        assert "collections.defaultdict" in registered

        assert "collections.deque" in registered


class TestItertoolsModels:
    """Test itertools module models."""

    def test_all_models_registered(self):
        """All expected models should be registered."""

        expected = [
            "chain",
            "islice",
            "groupby",
            "product",
            "permutations",
            "combinations",
            "count",
            "cycle",
            "repeat",
            "accumulate",
            "takewhile",
            "dropwhile",
            "zip_longest",
        ]

        for name in expected:
            assert name in ITERTOOLS_MODELS, f"Missing model: {name}"

    def test_get_chain_model(self):
        """Should retrieve chain model."""

        model = get_itertools_model("chain")

        assert model is model_chain

    def test_get_islice_model(self):
        """Should retrieve islice model."""

        model = get_itertools_model("islice")

        assert model is model_islice

    def test_get_product_model(self):
        """Should retrieve product model."""

        model = get_itertools_model("product")

        assert model is model_product

    def test_get_unknown_returns_none(self):
        """Unknown model should return None."""

        assert get_itertools_model("unknown_function") is None

    def test_register_creates_qualified_names(self):
        """Registration should create fully qualified names."""

        registered = register_itertools_models()

        assert "itertools.chain" in registered

        assert "itertools.islice" in registered

        assert "itertools.product" in registered

    def test_chain_from_iterable_registered(self):
        """chain.from_iterable should be registered."""

        assert "chain.from_iterable" in ITERTOOLS_MODELS


class TestFunctoolsModels:
    """Test functools module models."""

    def test_all_models_registered(self):
        """All expected models should be registered."""

        expected = [
            "partial",
            "reduce",
            "lru_cache",
            "cached_property",
            "wraps",
            "total_ordering",
            "cmp_to_key",
            "singledispatch",
        ]

        for name in expected:
            assert name in FUNCTOOLS_MODELS, f"Missing model: {name}"

    def test_get_partial_model(self):
        """Should retrieve partial model."""

        model = get_functools_model("partial")

        assert model is model_partial

    def test_get_reduce_model(self):
        """Should retrieve reduce model."""

        model = get_functools_model("reduce")

        assert model is model_reduce

    def test_get_unknown_returns_none(self):
        """Unknown model should return None."""

        assert get_functools_model("unknown_function") is None

    def test_register_creates_qualified_names(self):
        """Registration should create fully qualified names."""

        registered = register_functools_models()

        assert "functools.partial" in registered

        assert "functools.reduce" in registered

        assert "functools.lru_cache" in registered

    def test_partial_model_creation(self):
        """PartialModel should store function and args."""

        def test_func(a, b, c):
            return a + b + c

        partial = PartialModel(test_func, 1, 2)

        assert partial.func is test_func

        assert partial.args == (1, 2)

        assert partial.kwargs == {}

    def test_lru_cache_model_creation(self):
        """LRUCacheModel should store maxsize and typed."""

        cache = LRUCacheModel(maxsize=256, typed=True)

        assert cache.maxsize == 256

        assert cache.typed is True


class TestModelCounts:
    """Test the total number of models."""

    def test_collections_model_count(self):
        """Should have 5 collections models."""

        assert len(COLLECTIONS_MODELS) == 5

    def test_itertools_model_count(self):
        """Should have 15 itertools models."""

        assert len(ITERTOOLS_MODELS) == 15

    def test_functools_model_count(self):
        """Should have 8 functools models."""

        assert len(FUNCTOOLS_MODELS) == 8

    def test_total_model_count(self):
        """Total should be 28 stdlib models."""

        total = len(COLLECTIONS_MODELS) + len(ITERTOOLS_MODELS) + len(FUNCTOOLS_MODELS)

        assert total == 28
