"""Tests for pysymex._internal.models.stdlib.collections — all model classes + registry."""

from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr


class _FakeState:
    """Minimal VMState-like object for testing model_init calls."""

    pc: int = 0
    path_id: int = 0
    local_vars: dict[str, object] = {}


class TestCounterModel:
    """Test CounterModel static methods."""

    def test_model_init_returns_symbolic_dict(self) -> None:
        """Counter.__init__ returns an empty SymbolicDict."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.models.stdlib.collections.counter import CounterModel

        result = CounterModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(result, SymbolicDict)

    def test_model_most_common_returns_symbolic_list(self) -> None:
        """Counter.most_common returns a SymbolicList."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.models.stdlib.collections.counter import CounterModel

        counter = SymbolicDict.empty("counter")
        result = CounterModel.model_most_common(counter)
        assert isinstance(result, SymbolicList)

    def test_model_elements_returns_symbolic_list(self) -> None:
        """Counter.elements returns a SymbolicList."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.models.stdlib.collections.counter import CounterModel

        counter = SymbolicDict.empty("counter")
        result = CounterModel.model_elements(counter)
        assert isinstance(result, SymbolicList)

    def test_model_subtract_is_noop(self) -> None:
        """Counter.subtract() returns None (noop)."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.models.stdlib.collections.counter import CounterModel

        counter = SymbolicDict.empty("counter")
        result = CounterModel.model_subtract(counter)
        assert result is None

    def test_model_update_is_noop(self) -> None:
        """Counter.update() returns None (noop)."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.models.stdlib.collections.counter import CounterModel

        counter = SymbolicDict.empty("counter")
        result = CounterModel.model_update(counter)
        assert result is None


class TestDefaultDictModel:
    """Test DefaultDictModel static methods."""

    def test_model_init_sets_has_default_factory(self) -> None:
        """defaultdict.__init__ sets _has_default_factory on the result."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.models.stdlib.collections.defaultdict import DefaultDictModel

        dd = DefaultDictModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(dd, SymbolicDict)
        assert getattr(dd, "_has_default_factory", False) is True

    def test_model_getitem_returns_symbolic_value(self) -> None:
        """defaultdict[key] produces a SymbolicValue."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.core.types.scalars.values import SymbolicValue
        from pysymex._internal.models.stdlib.collections.defaultdict import DefaultDictModel

        dd = SymbolicDict.empty("dd")
        key, _ = SymbolicValue.symbolic("k")
        result = DefaultDictModel.model_getitem(dd, key)
        assert isinstance(result, SymbolicValue)

    def test_model_missing_returns_symbolic_value(self) -> None:
        """defaultdict.__missing__ produces a SymbolicValue."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.core.types.scalars.values import SymbolicValue
        from pysymex._internal.models.stdlib.collections.defaultdict import DefaultDictModel

        dd = SymbolicDict.empty("dd")
        key, _ = SymbolicValue.symbolic("k")
        result = DefaultDictModel.model_missing(dd, key)
        assert isinstance(result, SymbolicValue)


class TestDefaultDictRuntimeModels:
    """Test registered heap-backed ``defaultdict(int)`` constructor semantics."""

    def test_int_factory_creates_zero_default_dictionary_storage(self) -> None:
        from pysymex._internal.core.state.record import VMState
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.core.types.containers.objects import SymbolicObject
        from pysymex._internal.models.stdlib.collections.defaultdict import (
            DefaultDictConstructorModel,
        )

        state = VMState(pc=4)
        result = DefaultDictConstructorModel().apply([int], {}, state)

        assert isinstance(result.value, SymbolicObject)
        storage = state.load_heap(result.value.address)
        assert isinstance(storage, SymbolicDict)
        assert getattr(storage, "_has_default_factory", False) is True
        missing, presence = storage["missing"]
        assert z3.is_true(simplify_expr(presence))
        assert simplify_expr(missing.z3_int).as_long() == 0


class TestDequeModel:
    """Test DequeModel static methods."""

    def test_model_init_no_iterable(self) -> None:
        """deque() with no iterable returns empty SymbolicList."""
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.models.stdlib.collections.deque import DequeModel

        result = DequeModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(result, SymbolicList)

    def test_model_init_with_iterable(self) -> None:
        """deque(iterable) returns the iterable itself."""
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.models.stdlib.collections.deque import DequeModel

        lst = SymbolicList.empty("input")
        result = DequeModel.model_init(_FakeState(), iterable=lst)  # type: ignore[arg-type]
        assert result is lst

    def test_model_pop_returns_symbolic_value(self) -> None:
        """deque.pop() returns a SymbolicValue."""
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.core.types.scalars.values import SymbolicValue
        from pysymex._internal.models.stdlib.collections.deque import DequeModel

        deque = SymbolicList.empty("deque")
        result = DequeModel.model_pop(deque)
        assert isinstance(result, SymbolicValue)

    def test_model_popleft_returns_symbolic_value(self) -> None:
        """deque.popleft() returns a SymbolicValue."""
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.core.types.scalars.values import SymbolicValue
        from pysymex._internal.models.stdlib.collections.deque import DequeModel

        deque = SymbolicList.empty("deque")
        result = DequeModel.model_popleft(deque)
        assert isinstance(result, SymbolicValue)

    def test_model_clear_is_noop(self) -> None:
        """deque.clear() returns None."""
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.models.stdlib.collections.deque import DequeModel

        deque = SymbolicList.empty("deque")
        assert DequeModel.model_clear(deque) is None


class TestDequeRuntimeModels:
    """Test registered heap-backed deque call models."""

    def test_constructor_copies_symbolic_list_into_tagged_storage(self) -> None:
        from pysymex._internal.core.state.record import VMState
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.core.types.containers.objects import SymbolicObject
        from pysymex._internal.models.stdlib.collections.deque import DequeConstructorModel

        state = VMState()
        source = SymbolicList.from_const([3])
        result = DequeConstructorModel().apply([source], {}, state)

        assert isinstance(result.value, SymbolicObject)
        stored = state.memory[result.value.address]
        assert isinstance(stored, SymbolicList)
        assert getattr(stored, "_type", None) == "deque"
        assert stored.z3_len.as_long() == 1

    def test_popleft_reports_empty_index_error_and_removes_one_item(self) -> None:
        import z3

        from pysymex._internal.core.state.record import VMState
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.core.types.containers.objects import SymbolicObject
        from pysymex._internal.models.contracts.results import SideEffects
        from pysymex._internal.models.stdlib.collections.deque import DequePopleftModel

        state = VMState()
        storage = SymbolicList.from_const([3])
        setattr(storage, "_type", "deque")
        handle = SymbolicObject("deque", 1, z3.IntVal(1), {1})
        state.store_heap(1, storage)

        result = DequePopleftModel().apply([handle], {}, state)

        effect = result.side_effects.get("potential_exception")
        assert SideEffects.is_potential_exception(effect)
        assert effect["type"] == "IndexError"
        mutation = cast("dict[str, object]", result.side_effects["list_mutation"])
        updated = mutation["updated_list"]
        assert isinstance(updated, SymbolicList)
        assert simplify_expr(updated.z3_len).as_long() == 0


class TestOrderedDictModel:
    """Test OrderedDictModel static methods."""

    def test_model_init_returns_symbolic_dict(self) -> None:
        """OrderedDict() returns empty SymbolicDict."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.models.stdlib.collections.mappings import OrderedDictModel

        result = OrderedDictModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(result, SymbolicDict)

    def test_model_popitem_returns_tuple(self) -> None:
        """OrderedDict.popitem() returns (key, value) tuple."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.models.stdlib.collections.mappings import OrderedDictModel

        od = SymbolicDict.empty("od")
        result = OrderedDictModel.model_popitem(od)
        assert isinstance(result, tuple)
        assert len(result) == 2


class TestChainMapModel:
    """Test ChainMapModel static methods."""

    def test_model_init_returns_symbolic_dict(self) -> None:
        """ChainMap() returns empty SymbolicDict."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.models.stdlib.collections.mappings import ChainMapModel

        result = ChainMapModel.model_init(_FakeState())  # type: ignore[arg-type]
        assert isinstance(result, SymbolicDict)

    def test_model_new_child_returns_symbolic_dict(self) -> None:
        """ChainMap.new_child() returns empty SymbolicDict."""
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.models.stdlib.collections.mappings import ChainMapModel

        cm = SymbolicDict.empty("cm")
        result = ChainMapModel.model_new_child(cm)
        assert isinstance(result, SymbolicDict)
