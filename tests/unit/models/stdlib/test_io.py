from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from pysymex.core.state import VMState
from pysymex.core.types.containers import SymbolicList
from pysymex.core.types.scalars import SymbolicNone, SymbolicString, SymbolicValue


def _load_io_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "io.py"
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_io", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib io models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


io_models = _load_io_models()


def _state() -> VMState:
    return VMState(pc=0)


class TestCopyModel:
    """Test suite for pysymex.models.stdlib.io.CopyModel."""

    def test_faithfulness(self) -> None:
        result = io_models.CopyModel().apply([7], {}, _state())
        assert result.value == 7

    def test_error_path(self) -> None:
        io_models.CopyModel().apply([], {}, _state())


class TestDeepcopyModel:
    """Test suite for pysymex.models.stdlib.io.DeepcopyModel."""

    def test_faithfulness(self) -> None:
        io_models.DeepcopyModel().apply([1], {}, _state())

    def test_error_path(self) -> None:
        io_models.DeepcopyModel().apply([], {}, _state())


class TestStringIOModel:
    """Test suite for pysymex.models.stdlib.io.StringIOModel."""

    def test_faithfulness(self) -> None:
        io_models.StringIOModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        io_models.StringIOModel().apply(["x"], {}, _state())


class TestBytesIOModel:
    """Test suite for pysymex.models.stdlib.io.BytesIOModel."""

    def test_faithfulness(self) -> None:
        io_models.BytesIOModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        io_models.BytesIOModel().apply([b"x"], {}, _state())


class TestIOReadModel:
    """Test suite for pysymex.models.stdlib.io.IOReadModel."""

    def test_faithfulness(self) -> None:
        io_models.IOReadModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        io_models.IOReadModel().apply([1], {}, _state())


class TestIOWriteModel:
    """Test suite for pysymex.models.stdlib.io.IOWriteModel."""

    def test_faithfulness(self) -> None:
        sym = SymbolicString.from_const("abc")
        result = io_models.IOWriteModel().apply([sym], {}, _state())
        assert isinstance(result.value, SymbolicValue)

    def test_error_path(self) -> None:
        io_models.IOWriteModel().apply([], {}, _state())


class TestIOGetvalueModel:
    """Test suite for pysymex.models.stdlib.io.IOGetvalueModel."""

    def test_faithfulness(self) -> None:
        io_models.IOGetvalueModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        io_models.IOGetvalueModel().apply([1], {}, _state())


class TestHeappushModel:
    """Test suite for pysymex.models.stdlib.io.HeappushModel."""

    def test_faithfulness(self) -> None:
        result = io_models.HeappushModel().apply([[], 1], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = io_models.HeappushModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestHeappopModel:
    """Test suite for pysymex.models.stdlib.io.HeappopModel."""

    def test_faithfulness(self) -> None:
        io_models.HeappopModel().apply([[]], {}, _state())

    def test_error_path(self) -> None:
        io_models.HeappopModel().apply([], {}, _state())


class TestHeapifyModel:
    """Test suite for pysymex.models.stdlib.io.HeapifyModel."""

    def test_faithfulness(self) -> None:
        result = io_models.HeapifyModel().apply([[]], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = io_models.HeapifyModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestHeapreplaceModel:
    """Test suite for pysymex.models.stdlib.io.HeapreplaceModel."""

    def test_faithfulness(self) -> None:
        io_models.HeapreplaceModel().apply([[1], 2], {}, _state())

    def test_error_path(self) -> None:
        io_models.HeapreplaceModel().apply([], {}, _state())


class TestHeappushpopModel:
    """Test suite for pysymex.models.stdlib.io.HeappushpopModel."""

    def test_faithfulness(self) -> None:
        io_models.HeappushpopModel().apply([[1], 2], {}, _state())

    def test_error_path(self) -> None:
        io_models.HeappushpopModel().apply([], {}, _state())


class TestNlargestModel:
    """Test suite for pysymex.models.stdlib.io.NlargestModel."""

    def test_faithfulness(self) -> None:
        result = io_models.NlargestModel().apply([2, [1, 2, 3]], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = io_models.NlargestModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestNsmallestModel:
    """Test suite for pysymex.models.stdlib.io.NsmallestModel."""

    def test_faithfulness(self) -> None:
        result = io_models.NsmallestModel().apply([2, [1, 2, 3]], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = io_models.NsmallestModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestBisectLeftModel:
    """Test suite for pysymex.models.stdlib.io.BisectLeftModel."""

    def test_faithfulness(self) -> None:
        io_models.BisectLeftModel().apply([[1, 2, 3], 2], {}, _state())

    def test_error_path(self) -> None:
        io_models.BisectLeftModel().apply([], {}, _state())


class TestBisectRightModel:
    """Test suite for pysymex.models.stdlib.io.BisectRightModel."""

    def test_faithfulness(self) -> None:
        io_models.BisectRightModel().apply([[1, 2, 3], 2], {}, _state())

    def test_error_path(self) -> None:
        io_models.BisectRightModel().apply([], {}, _state())


class TestBisectModel:
    """Test suite for pysymex.models.stdlib.io.BisectModel."""

    def test_faithfulness(self) -> None:
        io_models.BisectModel().apply([[1, 2, 3], 2], {}, _state())

    def test_error_path(self) -> None:
        io_models.BisectModel().apply([], {}, _state())


class TestInsortLeftModel:
    """Test suite for pysymex.models.stdlib.io.InsortLeftModel."""

    def test_faithfulness(self) -> None:
        result = io_models.InsortLeftModel().apply([[1, 2], 3], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = io_models.InsortLeftModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestInsortRightModel:
    """Test suite for pysymex.models.stdlib.io.InsortRightModel."""

    def test_faithfulness(self) -> None:
        result = io_models.InsortRightModel().apply([[1, 2], 3], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = io_models.InsortRightModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestInsortModel:
    """Test suite for pysymex.models.stdlib.io.InsortModel."""

    def test_faithfulness(self) -> None:
        result = io_models.InsortModel().apply([[1, 2], 3], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = io_models.InsortModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)
