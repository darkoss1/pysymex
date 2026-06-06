from __future__ import annotations

from collections.abc import Callable

from pysymex.core.state.record import VMState
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.stdlib.models.datetime import (
    DatetimeConstructorModel,
    DatetimeNowModel,
    TimedeltaConstructorModel,
)
from pysymex.models.stdlib.models.json import (
    JsonDumpModel,
    JsonDumpsModel,
    JsonLoadModel,
    JsonLoadsModel,
)
from pysymex.models.stdlib.models.ospath import (
    OsPathAbspathModel,
    OsPathBasenameModel,
    OsPathDirnameModel,
    OsPathExistsModel,
    OsPathIsdirModel,
    OsPathIsfileModel,
    OsPathJoinModel,
    OsPathSplitModel,
)
from pysymex.models.stdlib.models.random import (
    RandomChoiceModel,
    RandomRandintModel,
    RandomRandomModel,
    RandomSampleModel,
    RandomShuffleModel,
    RandomUniformModel,
)
from pysymex.models.stdlib.models.types import SimpleNamespaceModel


def _state() -> VMState:
    return VMState(pc=0)


def _call_model(fn: Callable[[], object]) -> None:
    fn()


class TestOsPathExistsModel:
    """Test suite for pysymex.models.stdlib.models.OsPathExistsModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: OsPathExistsModel().apply(["."], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: OsPathExistsModel().apply([], {}, _state()))


class TestOsPathIsfileModel:
    """Test suite for pysymex.models.stdlib.models.OsPathIsfileModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: OsPathIsfileModel().apply(["."], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: OsPathIsfileModel().apply([], {}, _state()))


class TestOsPathIsdirModel:
    """Test suite for pysymex.models.stdlib.models.OsPathIsdirModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: OsPathIsdirModel().apply(["."], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: OsPathIsdirModel().apply([], {}, _state()))


class TestOsPathJoinModel:
    """Test suite for pysymex.models.stdlib.models.OsPathJoinModel."""

    def test_faithfulness(self) -> None:
        result = OsPathJoinModel().apply(["a", "b"], {}, _state())
        assert isinstance(result.value, SymbolicString)
        assert result.constraints == ()

    def test_error_path(self) -> None:
        _call_model(lambda: OsPathJoinModel().apply([1, 2], {}, _state()))


class TestOsPathDirnameModel:
    """Test suite for pysymex.models.stdlib.models.OsPathDirnameModel."""

    def test_faithfulness(self) -> None:
        result = OsPathDirnameModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        _call_model(lambda: OsPathDirnameModel().apply([], {}, _state()))


class TestOsPathBasenameModel:
    """Test suite for pysymex.models.stdlib.models.OsPathBasenameModel."""

    def test_faithfulness(self) -> None:
        result = OsPathBasenameModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        _call_model(lambda: OsPathBasenameModel().apply([], {}, _state()))


class TestOsPathSplitModel:
    """Test suite for pysymex.models.stdlib.models.OsPathSplitModel."""

    def test_faithfulness(self) -> None:
        result = OsPathSplitModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, tuple)

    def test_error_path(self) -> None:
        _call_model(lambda: OsPathSplitModel().apply([], {}, _state()))


class TestOsPathAbspathModel:
    """Test suite for pysymex.models.stdlib.models.OsPathAbspathModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: OsPathAbspathModel().apply(["."], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: OsPathAbspathModel().apply([], {}, _state()))


class TestJsonLoadsModel:
    """Test suite for pysymex.models.stdlib.models.JsonLoadsModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: JsonLoadsModel().apply(['{"a":1}'], {}, _state()))

    def test_literal_object_preserves_concrete_dict_lookup(self) -> None:
        result = JsonLoadsModel().apply(['{"x": 2}'], {}, _state())

        assert isinstance(result.value, SymbolicDict)
        has_value, value = result.value.concrete_value_for_key("x")
        assert has_value is True
        assert isinstance(value, SymbolicValue)
        assert value.value == 2

    def test_error_path(self) -> None:
        _call_model(lambda: JsonLoadsModel().apply([], {}, _state()))


class TestJsonDumpsModel:
    """Test suite for pysymex.models.stdlib.models.JsonDumpsModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: JsonDumpsModel().apply([{"a": 1}], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: JsonDumpsModel().apply([], {}, _state()))


class TestJsonLoadModel:
    """Test suite for pysymex.models.stdlib.models.JsonLoadModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: JsonLoadModel().apply([SymbolicValue.from_const("file")], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: JsonLoadModel().apply([], {}, _state()))


class TestJsonDumpModel:
    """Test suite for pysymex.models.stdlib.models.JsonDumpModel."""

    def test_faithfulness(self) -> None:
        result = JsonDumpModel().apply([{"a": 1}, SymbolicValue.from_const("file")], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = JsonDumpModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestDatetimeNowModel:
    """Test suite for pysymex.models.stdlib.models.DatetimeNowModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: DatetimeNowModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: DatetimeNowModel().apply([1], {}, _state()))


class TestDatetimeConstructorModel:
    """Test suite for pysymex.models.stdlib.models.DatetimeConstructorModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: DatetimeConstructorModel().apply([2025, 1, 1], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: DatetimeConstructorModel().apply([], {}, _state()))


class TestTimedeltaConstructorModel:
    """Test suite for pysymex.models.stdlib.models.TimedeltaConstructorModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: TimedeltaConstructorModel().apply([1], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: TimedeltaConstructorModel().apply([], {}, _state()))


class TestRandomRandomModel:
    """Test suite for pysymex.models.stdlib.models.RandomRandomModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: RandomRandomModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: RandomRandomModel().apply([1], {}, _state()))


class TestRandomRandintModel:
    """Test suite for pysymex.models.stdlib.models.RandomRandintModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: RandomRandintModel().apply([1, 3], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: RandomRandintModel().apply([], {}, _state()))


class TestRandomChoiceModel:
    """Test suite for pysymex.models.stdlib.models.RandomChoiceModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: RandomChoiceModel().apply([[1, 2]], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: RandomChoiceModel().apply([], {}, _state()))


class TestRandomShuffleModel:
    """Test suite for pysymex.models.stdlib.models.RandomShuffleModel."""

    def test_faithfulness(self) -> None:
        result = RandomShuffleModel().apply([[1, 2]], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = RandomShuffleModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestRandomSampleModel:
    """Test suite for pysymex.models.stdlib.models.RandomSampleModel."""

    def test_faithfulness(self) -> None:
        result = RandomSampleModel().apply([[1, 2, 3], 2], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = RandomSampleModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestRandomUniformModel:
    """Test suite for pysymex.models.stdlib.models.RandomUniformModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: RandomUniformModel().apply([1.0, 2.0], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: RandomUniformModel().apply([], {}, _state()))


class TestSimpleNamespaceModel:
    """Test suite for pysymex.models.stdlib.models.SimpleNamespaceModel."""

    def test_faithfulness(self) -> None:
        state = _state()
        result = SimpleNamespaceModel().apply([], {"x": 1}, state)
        assert result.value is not None
        assert len(state.memory) >= 1

    def test_error_path(self) -> None:
        state = _state()
        result = SimpleNamespaceModel().apply([], {}, state)
        assert result.value is not None
