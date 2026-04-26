"""Tests for pysymex.models.stdlib.collections — all model classes + registry."""

from __future__ import annotations

import sys


class _FakeState:
    """Minimal VMState-like object for testing model_init calls."""

    pc: int = 0
    path_id: int = 0
    local_vars: dict[str, object] = {}


class TestCounterModel:
    """Test CounterModel static methods."""

    def test_model_init_returns_symbolic_dict(self) -> None:
        """Counter.__init__ returns an empty SymbolicDict."""
        from pysymex.models.stdlib.collections import CounterModel
        from pysymex.core.types.containers import SymbolicDict

        result = CounterModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(result, SymbolicDict)

    def test_model_most_common_returns_symbolic_list(self) -> None:
        """Counter.most_common returns a SymbolicList."""
        from pysymex.models.stdlib.collections import CounterModel
        from pysymex.core.types.containers import SymbolicDict, SymbolicList

        counter = SymbolicDict.empty("counter")
        result = CounterModel.model_most_common(counter)
        assert isinstance(result, SymbolicList)

    def test_model_elements_returns_symbolic_list(self) -> None:
        """Counter.elements returns a SymbolicList."""
        from pysymex.models.stdlib.collections import CounterModel
        from pysymex.core.types.containers import SymbolicDict, SymbolicList

        counter = SymbolicDict.empty("counter")
        result = CounterModel.model_elements(counter)
        assert isinstance(result, SymbolicList)

    def test_model_subtract_is_noop(self) -> None:
        """Counter.subtract() returns None (noop)."""
        from pysymex.models.stdlib.collections import CounterModel
        from pysymex.core.types.containers import SymbolicDict

        counter = SymbolicDict.empty("counter")
        result = CounterModel.model_subtract(counter)
        assert result is None

    def test_model_update_is_noop(self) -> None:
        """Counter.update() returns None (noop)."""
        from pysymex.models.stdlib.collections import CounterModel
        from pysymex.core.types.containers import SymbolicDict

        counter = SymbolicDict.empty("counter")
        result = CounterModel.model_update(counter)
        assert result is None


class TestDefaultDictModel:
    """Test DefaultDictModel static methods."""

    def test_model_init_sets_has_default_factory(self) -> None:
        """defaultdict.__init__ sets _has_default_factory on the result."""
        from pysymex.models.stdlib.collections import DefaultDictModel
        from pysymex.core.types.containers import SymbolicDict

        dd = DefaultDictModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(dd, SymbolicDict)
        assert getattr(dd, "_has_default_factory", False) is True

    def test_model_getitem_returns_symbolic_value(self) -> None:
        """defaultdict[key] produces a SymbolicValue."""
        from pysymex.models.stdlib.collections import DefaultDictModel
        from pysymex.core.types.scalars import SymbolicValue
        from pysymex.core.types.containers import SymbolicDict

        dd = SymbolicDict.empty("dd")
        key, _ = SymbolicValue.symbolic("k")
        result = DefaultDictModel.model_getitem(dd, key)
        assert isinstance(result, SymbolicValue)

    def test_model_missing_returns_symbolic_value(self) -> None:
        """defaultdict.__missing__ produces a SymbolicValue."""
        from pysymex.models.stdlib.collections import DefaultDictModel
        from pysymex.core.types.scalars import SymbolicValue
        from pysymex.core.types.containers import SymbolicDict

        dd = SymbolicDict.empty("dd")
        key, _ = SymbolicValue.symbolic("k")
        result = DefaultDictModel.model_missing(dd, key)
        assert isinstance(result, SymbolicValue)


class TestDequeModel:
    """Test DequeModel static methods."""

    def test_model_init_no_iterable(self) -> None:
        """deque() with no iterable returns empty SymbolicList."""
        from pysymex.models.stdlib.collections import DequeModel
        from pysymex.core.types.containers import SymbolicList

        result = DequeModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(result, SymbolicList)

    def test_model_init_with_iterable(self) -> None:
        """deque(iterable) returns the iterable itself."""
        from pysymex.models.stdlib.collections import DequeModel
        from pysymex.core.types.containers import SymbolicList

        lst = SymbolicList.empty("input")
        result = DequeModel.model_init(_FakeState(), iterable=lst)  # type: ignore[arg-type]
        assert result is lst

    def test_model_pop_returns_symbolic_value(self) -> None:
        """deque.pop() returns a SymbolicValue."""
        from pysymex.models.stdlib.collections import DequeModel
        from pysymex.core.types.scalars import SymbolicValue
        from pysymex.core.types.containers import SymbolicList

        deque = SymbolicList.empty("deque")
        result = DequeModel.model_pop(deque)
        assert isinstance(result, SymbolicValue)

    def test_model_popleft_returns_symbolic_value(self) -> None:
        """deque.popleft() returns a SymbolicValue."""
        from pysymex.models.stdlib.collections import DequeModel
        from pysymex.core.types.scalars import SymbolicValue
        from pysymex.core.types.containers import SymbolicList

        deque = SymbolicList.empty("deque")
        result = DequeModel.model_popleft(deque)
        assert isinstance(result, SymbolicValue)

    def test_model_append_is_noop(self) -> None:
        """deque.append() returns None."""
        from pysymex.models.stdlib.collections import DequeModel
        from pysymex.core.types.scalars import SymbolicValue
        from pysymex.core.types.containers import SymbolicList

        deque = SymbolicList.empty("deque")
        v, _ = SymbolicValue.symbolic("x")
        assert DequeModel.model_append(deque, v) is None

    def test_model_rotate_is_noop(self) -> None:
        """deque.rotate() returns None."""
        from pysymex.models.stdlib.collections import DequeModel
        from pysymex.core.types.containers import SymbolicList

        deque = SymbolicList.empty("deque")
        assert DequeModel.model_rotate(deque, 2) is None

    def test_model_clear_is_noop(self) -> None:
        """deque.clear() returns None."""
        from pysymex.models.stdlib.collections import DequeModel
        from pysymex.core.types.containers import SymbolicList

        deque = SymbolicList.empty("deque")
        assert DequeModel.model_clear(deque) is None


class TestOrderedDictModel:
    """Test OrderedDictModel static methods."""

    def test_model_init_returns_symbolic_dict(self) -> None:
        """OrderedDict() returns empty SymbolicDict."""
        from pysymex.models.stdlib.collections import OrderedDictModel
        from pysymex.core.types.containers import SymbolicDict

        result = OrderedDictModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(result, SymbolicDict)

    def test_model_popitem_returns_tuple(self) -> None:
        """OrderedDict.popitem() returns (key, value) tuple."""
        from pysymex.models.stdlib.collections import OrderedDictModel
        from pysymex.core.types.scalars import SymbolicValue
        from pysymex.core.types.containers import SymbolicDict

        od = SymbolicDict.empty("od")
        result = OrderedDictModel.model_popitem(od)
        assert isinstance(result, tuple)
        assert len(result) == 2


class TestChainMapModel:
    """Test ChainMapModel static methods."""

    def test_model_init_returns_symbolic_dict(self) -> None:
        """ChainMap() returns empty SymbolicDict."""
        from pysymex.models.stdlib.collections import ChainMapModel
        from pysymex.core.types.containers import SymbolicDict

        result = ChainMapModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(result, SymbolicDict)

    def test_model_new_child_returns_symbolic_dict(self) -> None:
        """ChainMap.new_child() returns empty SymbolicDict."""
        from pysymex.models.stdlib.collections import ChainMapModel
        from pysymex.core.types.containers import SymbolicDict

        cm = SymbolicDict.empty("cm")
        result = ChainMapModel.model_new_child(cm)
        assert isinstance(result, SymbolicDict)


class TestGetCollectionsModel:
    """Test get_collections_model registry lookup."""

    def test_known_model_returns_class(self) -> None:
        """Known names return the model class."""
        from pysymex.models.stdlib.collections import (
            get_collections_model,
            CounterModel,
            DequeModel,
        )

        assert get_collections_model("Counter") is CounterModel
        assert get_collections_model("deque") is DequeModel

    def test_unknown_model_returns_none(self) -> None:
        """Unknown names return None."""
        from pysymex.models.stdlib.collections import get_collections_model

        assert get_collections_model("NonExistent") is None


class TestRegisterCollectionsModels:
    """Test register_collections_models."""

    def test_returns_full_qualified_mapping(self) -> None:
        """All models are returned with 'collections.' prefix."""
        from pysymex.models.stdlib.collections import register_collections_models

        registry = register_collections_models()
        assert "collections.Counter" in registry
        assert "collections.deque" in registry
        assert "collections.OrderedDict" in registry
        assert "collections.defaultdict" in registry
        assert "collections.ChainMap" in registry
        assert len(registry) == 5
