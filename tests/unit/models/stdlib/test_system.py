from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicList, SymbolicNone, SymbolicString


def _load_system_models() -> ModuleType:
    module_path = (
        Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "system.py"
    )
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_system", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib system models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


system_models = _load_system_models()


def _state() -> VMState:
    return VMState(pc=0)


def _call_model(fn: object) -> None:
    fn()


class TestOsPathExistsModel:
    """Test suite for pysymex.models.stdlib.system.OsPathExistsModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.OsPathExistsModel().apply(["."], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.OsPathExistsModel().apply([], {}, _state()))


class TestOsPathIsfileModel:
    """Test suite for pysymex.models.stdlib.system.OsPathIsfileModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.OsPathIsfileModel().apply(["."], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.OsPathIsfileModel().apply([], {}, _state()))


class TestOsPathIsdirModel:
    """Test suite for pysymex.models.stdlib.system.OsPathIsdirModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.OsPathIsdirModel().apply(["."], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.OsPathIsdirModel().apply([], {}, _state()))


class TestOsPathJoinModel:
    """Test suite for pysymex.models.stdlib.system.OsPathJoinModel."""

    def test_faithfulness(self) -> None:
        result = system_models.OsPathJoinModel().apply(["a", "b"], {}, _state())
        assert isinstance(result.value, SymbolicString)
        assert result.constraints == ()

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.OsPathJoinModel().apply([1, 2], {}, _state()))


class TestOsPathDirnameModel:
    """Test suite for pysymex.models.stdlib.system.OsPathDirnameModel."""

    def test_faithfulness(self) -> None:
        result = system_models.OsPathDirnameModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.OsPathDirnameModel().apply([], {}, _state()))


class TestOsPathBasenameModel:
    """Test suite for pysymex.models.stdlib.system.OsPathBasenameModel."""

    def test_faithfulness(self) -> None:
        result = system_models.OsPathBasenameModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, SymbolicString)

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.OsPathBasenameModel().apply([], {}, _state()))


class TestOsPathSplitModel:
    """Test suite for pysymex.models.stdlib.system.OsPathSplitModel."""

    def test_faithfulness(self) -> None:
        result = system_models.OsPathSplitModel().apply(["a/b"], {}, _state())
        assert isinstance(result.value, tuple)

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.OsPathSplitModel().apply([], {}, _state()))


class TestOsPathAbspathModel:
    """Test suite for pysymex.models.stdlib.system.OsPathAbspathModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.OsPathAbspathModel().apply(["."], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.OsPathAbspathModel().apply([], {}, _state()))


class TestJsonLoadsModel:
    """Test suite for pysymex.models.stdlib.system.JsonLoadsModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.JsonLoadsModel().apply(['{"a":1}'], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.JsonLoadsModel().apply([], {}, _state()))


class TestJsonDumpsModel:
    """Test suite for pysymex.models.stdlib.system.JsonDumpsModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.JsonDumpsModel().apply([{"a": 1}], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.JsonDumpsModel().apply([], {}, _state()))


class TestJsonLoadModel:
    """Test suite for pysymex.models.stdlib.system.JsonLoadModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.JsonLoadModel().apply([object()], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.JsonLoadModel().apply([], {}, _state()))


class TestJsonDumpModel:
    """Test suite for pysymex.models.stdlib.system.JsonDumpModel."""

    def test_faithfulness(self) -> None:
        result = system_models.JsonDumpModel().apply([{"a": 1}, object()], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = system_models.JsonDumpModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestDatetimeNowModel:
    """Test suite for pysymex.models.stdlib.system.DatetimeNowModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.DatetimeNowModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.DatetimeNowModel().apply([1], {}, _state()))


class TestDatetimeConstructorModel:
    """Test suite for pysymex.models.stdlib.system.DatetimeConstructorModel."""

    def test_faithfulness(self) -> None:
        _call_model(
            lambda: system_models.DatetimeConstructorModel().apply([2025, 1, 1], {}, _state())
        )

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.DatetimeConstructorModel().apply([], {}, _state()))


class TestTimedeltaConstructorModel:
    """Test suite for pysymex.models.stdlib.system.TimedeltaConstructorModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.TimedeltaConstructorModel().apply([1], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.TimedeltaConstructorModel().apply([], {}, _state()))


class TestRandomRandomModel:
    """Test suite for pysymex.models.stdlib.system.RandomRandomModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.RandomRandomModel().apply([], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.RandomRandomModel().apply([1], {}, _state()))


class TestRandomRandintModel:
    """Test suite for pysymex.models.stdlib.system.RandomRandintModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.RandomRandintModel().apply([1, 3], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.RandomRandintModel().apply([], {}, _state()))


class TestRandomChoiceModel:
    """Test suite for pysymex.models.stdlib.system.RandomChoiceModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.RandomChoiceModel().apply([[1, 2]], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.RandomChoiceModel().apply([], {}, _state()))


class TestRandomShuffleModel:
    """Test suite for pysymex.models.stdlib.system.RandomShuffleModel."""

    def test_faithfulness(self) -> None:
        result = system_models.RandomShuffleModel().apply([[1, 2]], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = system_models.RandomShuffleModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestRandomSampleModel:
    """Test suite for pysymex.models.stdlib.system.RandomSampleModel."""

    def test_faithfulness(self) -> None:
        result = system_models.RandomSampleModel().apply([[1, 2, 3], 2], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = system_models.RandomSampleModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestRandomUniformModel:
    """Test suite for pysymex.models.stdlib.system.RandomUniformModel."""

    def test_faithfulness(self) -> None:
        _call_model(lambda: system_models.RandomUniformModel().apply([1.0, 2.0], {}, _state()))

    def test_error_path(self) -> None:
        _call_model(lambda: system_models.RandomUniformModel().apply([], {}, _state()))


class TestSimpleNamespaceModel:
    """Test suite for pysymex.models.stdlib.system.SimpleNamespaceModel."""

    def test_faithfulness(self) -> None:
        state = _state()
        result = system_models.SimpleNamespaceModel().apply([], {"x": 1}, state)
        assert result.value is not None
        assert len(state.memory) >= 1

    def test_error_path(self) -> None:
        state = _state()
        result = system_models.SimpleNamespaceModel().apply([], {}, state)
        assert result.value is not None
