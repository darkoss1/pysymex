from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.stdlib.collections.counter import CounterModel
from pysymex._internal.models.stdlib.collections.defaultdict import DefaultDictModel
from pysymex._internal.models.stdlib.collections.deque import DequeModel
from pysymex._internal.models.stdlib.collections.mappings import ChainMapModel, OrderedDictModel


def _state() -> VMState:
    return VMState(pc=0)


def _call_model(fn: object) -> None:
    if callable(fn):
        fn()


class TestCounterModel:
    """Test suite for pysymex._internal.models.stdlib.collections.CounterModel."""

    def test_faithfulness(self) -> None:
        counter = CounterModel.model_init(_state())
        assert isinstance(counter, SymbolicDict)
        assert isinstance(CounterModel.model_most_common(counter), SymbolicList)
        assert isinstance(CounterModel.model_elements(counter), SymbolicList)
        assert CounterModel.model_subtract(counter) is None
        assert CounterModel.model_update(counter) is None

    def test_error_path(self) -> None:
        counter = CounterModel.model_init(_state())
        assert CounterModel.model_subtract(counter, None) is None
        assert CounterModel.model_update(counter, None) is None


class TestDefaultDictModel:
    """Test suite for pysymex._internal.models.stdlib.collections.DefaultDictModel."""

    def test_faithfulness(self) -> None:
        dd = DefaultDictModel.model_init(_state(), list)
        assert isinstance(dd, SymbolicDict)
        assert getattr(dd, "_has_default_factory") is True

    def test_error_path(self) -> None:
        dd = DefaultDictModel.model_init(_state())
        key = SymbolicValue.from_const("k")
        _call_model(lambda: DefaultDictModel.model_getitem(dd, key))
        _call_model(lambda: DefaultDictModel.model_missing(dd, key))


class TestDequeModel:
    """Test suite for pysymex._internal.models.stdlib.collections.DequeModel."""

    def test_faithfulness(self) -> None:
        dq = DequeModel.model_init(_state())
        assert isinstance(dq, SymbolicList)
        assert DequeModel.model_extend(dq, SymbolicList.empty("src")) is None
        assert DequeModel.model_extendleft(dq, SymbolicList.empty("src")) is None
        assert DequeModel.model_clear(dq) is None

    def test_error_path(self) -> None:
        dq = DequeModel.model_init(_state())
        _call_model(lambda: DequeModel.model_pop(dq))
        _call_model(lambda: DequeModel.model_popleft(dq))


class TestOrderedDictModel:
    """Test suite for pysymex._internal.models.stdlib.collections.OrderedDictModel."""

    def test_faithfulness(self) -> None:
        od = OrderedDictModel.model_init(_state())
        assert isinstance(od, SymbolicDict)
        assert OrderedDictModel.model_move_to_end(od, SymbolicValue.from_const("k")) is None

    def test_error_path(self) -> None:
        od = OrderedDictModel.model_init(_state())
        _call_model(lambda: OrderedDictModel.model_popitem(od))


class TestChainMapModel:
    """Test suite for pysymex._internal.models.stdlib.collections.ChainMapModel."""

    def test_faithfulness(self) -> None:
        cm = ChainMapModel.model_init(_state())
        assert isinstance(cm, SymbolicDict)
        child = ChainMapModel.model_new_child(cm)
        assert isinstance(child, SymbolicDict)

    def test_error_path(self) -> None:
        cm = ChainMapModel.model_init(_state())
        child = ChainMapModel.model_new_child(cm, None)
        assert isinstance(child, SymbolicDict)
