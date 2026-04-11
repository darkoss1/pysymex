from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicDict, SymbolicList, SymbolicValue


def _load_collections_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "collections.py"
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_collections", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib collections models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collections_models = _load_collections_models()


def _state() -> VMState:
    return VMState(pc=0)


def _assert_nameerror(fn: object) -> None:
    with pytest.raises(NameError):
        assert callable(fn)
        fn()


class TestCounterModel:
    """Test suite for pysymex.models.stdlib.collections.CounterModel."""

    def test_faithfulness(self) -> None:
        counter = collections_models.CounterModel.model_init(_state())
        assert isinstance(counter, SymbolicDict)
        assert isinstance(collections_models.CounterModel.model_most_common(counter), SymbolicList)
        assert isinstance(collections_models.CounterModel.model_elements(counter), SymbolicList)
        assert collections_models.CounterModel.model_subtract(counter) is None
        assert collections_models.CounterModel.model_update(counter) is None

    def test_error_path(self) -> None:
        counter = collections_models.CounterModel.model_init(_state())
        assert collections_models.CounterModel.model_subtract(counter, None) is None
        assert collections_models.CounterModel.model_update(counter, None) is None


class TestDefaultDictModel:
    """Test suite for pysymex.models.stdlib.collections.DefaultDictModel."""

    def test_faithfulness(self) -> None:
        dd = collections_models.DefaultDictModel.model_init(_state(), list)
        assert isinstance(dd, SymbolicDict)
        assert getattr(dd, "_has_default_factory") is True

    def test_error_path(self) -> None:
        dd = collections_models.DefaultDictModel.model_init(_state())
        key = SymbolicValue.from_const("k")
        _assert_nameerror(lambda: collections_models.DefaultDictModel.model_getitem(dd, key))
        _assert_nameerror(lambda: collections_models.DefaultDictModel.model_missing(dd, key))


class TestDequeModel:
    """Test suite for pysymex.models.stdlib.collections.DequeModel."""

    def test_faithfulness(self) -> None:
        dq = collections_models.DequeModel.model_init(_state())
        assert isinstance(dq, SymbolicList)
        assert collections_models.DequeModel.model_append(dq, SymbolicValue.from_const(1)) is None
        assert collections_models.DequeModel.model_appendleft(dq, SymbolicValue.from_const(1)) is None
        assert collections_models.DequeModel.model_rotate(dq, 1) is None
        assert collections_models.DequeModel.model_extend(dq, SymbolicList.empty("src")) is None
        assert collections_models.DequeModel.model_extendleft(dq, SymbolicList.empty("src")) is None
        assert collections_models.DequeModel.model_clear(dq) is None

    def test_error_path(self) -> None:
        dq = collections_models.DequeModel.model_init(_state())
        _assert_nameerror(lambda: collections_models.DequeModel.model_pop(dq))
        _assert_nameerror(lambda: collections_models.DequeModel.model_popleft(dq))


class TestOrderedDictModel:
    """Test suite for pysymex.models.stdlib.collections.OrderedDictModel."""

    def test_faithfulness(self) -> None:
        od = collections_models.OrderedDictModel.model_init(_state())
        assert isinstance(od, SymbolicDict)
        assert collections_models.OrderedDictModel.model_move_to_end(od, SymbolicValue.from_const("k")) is None

    def test_error_path(self) -> None:
        od = collections_models.OrderedDictModel.model_init(_state())
        _assert_nameerror(lambda: collections_models.OrderedDictModel.model_popitem(od))


class TestChainMapModel:
    """Test suite for pysymex.models.stdlib.collections.ChainMapModel."""

    def test_faithfulness(self) -> None:
        cm = collections_models.ChainMapModel.model_init(_state())
        assert isinstance(cm, SymbolicDict)
        child = collections_models.ChainMapModel.model_new_child(cm)
        assert isinstance(child, SymbolicDict)

    def test_error_path(self) -> None:
        cm = collections_models.ChainMapModel.model_init(_state())
        child = collections_models.ChainMapModel.model_new_child(cm, None)
        assert isinstance(child, SymbolicDict)


def test_get_collections_model() -> None:
    """Test get_collections_model behavior."""
    assert collections_models.get_collections_model("Counter") is collections_models.CounterModel
    assert collections_models.get_collections_model("missing") is None


def test_register_collections_models() -> None:
    """Test register_collections_models behavior."""
    registered = collections_models.register_collections_models()
    assert registered["collections.Counter"] is collections_models.CounterModel
    assert registered["collections.deque"] is collections_models.DequeModel
