from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue


def _load_data_models() -> ModuleType:
    module_path = Path(__file__).resolve().parents[4] / "pysymex" / "models" / "stdlib" / "data.py"
    spec = importlib.util.spec_from_file_location("pysymex_models_stdlib_data", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load stdlib data models module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


data_models = _load_data_models()


def _state() -> VMState:
    return VMState(pc=0)


class TestEnumModel:
    """Test suite for pysymex.models.stdlib.data.EnumModel."""

    def test_faithfulness(self) -> None:
        data_models.EnumModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        data_models.EnumModel().apply([1], {}, _state())


class TestIntEnumModel:
    """Test suite for pysymex.models.stdlib.data.IntEnumModel."""

    def test_faithfulness(self) -> None:
        data_models.IntEnumModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        data_models.IntEnumModel().apply([1], {}, _state())


class TestEnumAutoModel:
    """Test suite for pysymex.models.stdlib.data.EnumAutoModel."""

    def test_faithfulness(self) -> None:
        data_models.EnumAutoModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        data_models.EnumAutoModel().apply([1], {}, _state())


class TestEnumValueModel:
    """Test suite for pysymex.models.stdlib.data.EnumValueModel."""

    def test_faithfulness(self) -> None:
        data_models.EnumValueModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        data_models.EnumValueModel().apply([1], {}, _state())


class TestEnumNameModel:
    """Test suite for pysymex.models.stdlib.data.EnumNameModel."""

    def test_faithfulness(self) -> None:
        data_models.EnumNameModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        data_models.EnumNameModel().apply([1], {}, _state())


class TestDataclassModel:
    """Test suite for pysymex.models.stdlib.data.DataclassModel."""

    def test_faithfulness(self) -> None:
        marker = object()
        result = data_models.DataclassModel().apply([marker], {}, _state())
        assert result.value is marker

    def test_error_path(self) -> None:
        data_models.DataclassModel().apply([], {}, _state())


class TestDataclassFieldModel:
    """Test suite for pysymex.models.stdlib.data.DataclassFieldModel."""

    def test_faithfulness(self) -> None:
        result = data_models.DataclassFieldModel().apply([], {"default": 5}, _state())
        assert result.value == 5

    def test_error_path(self) -> None:
        data_models.DataclassFieldModel().apply([], {}, _state())


class TestAsDataclassModel:
    """Test suite for pysymex.models.stdlib.data.AsDataclassModel."""

    def test_faithfulness(self) -> None:
        result = data_models.AsDataclassModel().apply([], {}, _state())
        assert result.value is not None

    def test_error_path(self) -> None:
        result = data_models.AsDataclassModel().apply([1], {}, _state())
        assert result.value is not None


class TestAstupleModel:
    """Test suite for pysymex.models.stdlib.data.AstupleModel."""

    def test_faithfulness(self) -> None:
        result = data_models.AstupleModel().apply([], {}, _state())
        assert result.value is not None

    def test_error_path(self) -> None:
        result = data_models.AstupleModel().apply([1], {}, _state())
        assert result.value is not None


class TestFieldsModel:
    """Test suite for pysymex.models.stdlib.data.FieldsModel."""

    def test_faithfulness(self) -> None:
        result = data_models.FieldsModel().apply([], {}, _state())
        assert result.value is not None

    def test_error_path(self) -> None:
        result = data_models.FieldsModel().apply([1], {}, _state())
        assert result.value is not None


class TestReplaceModel:
    """Test suite for pysymex.models.stdlib.data.ReplaceModel."""

    def test_faithfulness(self) -> None:
        result = data_models.ReplaceModel().apply([object()], {"x": 1}, _state())
        assert result.value is not None

    def test_error_path(self) -> None:
        data_models.ReplaceModel().apply([], {}, _state())


class TestOperatorItemgetterModel:
    """Test suite for pysymex.models.stdlib.data.OperatorItemgetterModel."""

    def test_faithfulness(self) -> None:
        data_models.OperatorItemgetterModel().apply([0], {}, _state())
        data_models.OperatorItemgetterModel().apply([0], {}, _state())

    def test_error_path(self) -> None:
        data_models.OperatorItemgetterModel().apply([], {}, _state())


class TestOperatorAttrgetterModel:
    """Test suite for pysymex.models.stdlib.data.OperatorAttrgetterModel."""

    def test_faithfulness(self) -> None:
        data_models.OperatorAttrgetterModel().apply(["x"], {}, _state())

    def test_error_path(self) -> None:
        data_models.OperatorAttrgetterModel().apply([], {}, _state())


class TestOperatorAddModel:
    """Test suite for pysymex.models.stdlib.data.OperatorAddModel."""

    def test_faithfulness(self) -> None:
        result = data_models.OperatorAddModel().apply([2, 3], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 5

    def test_error_path(self) -> None:
        data_models.OperatorAddModel().apply([], {}, _state())


class TestOperatorSubModel:
    """Test suite for pysymex.models.stdlib.data.OperatorSubModel."""

    def test_faithfulness(self) -> None:
        result = data_models.OperatorSubModel().apply([7, 3], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 4

    def test_error_path(self) -> None:
        data_models.OperatorSubModel().apply([], {}, _state())


class TestOperatorMulModel:
    """Test suite for pysymex.models.stdlib.data.OperatorMulModel."""

    def test_faithfulness(self) -> None:
        result = data_models.OperatorMulModel().apply([4, 3], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 12

    def test_error_path(self) -> None:
        data_models.OperatorMulModel().apply([], {}, _state())


class TestOperatorTruedivModel:
    """Test suite for pysymex.models.stdlib.data.OperatorTruedivModel."""

    def test_faithfulness(self) -> None:
        data_models.OperatorTruedivModel().apply([4, 2], {}, _state())

    def test_error_path(self) -> None:
        data_models.OperatorTruedivModel().apply([], {}, _state())


class TestOperatorFloordivModel:
    """Test suite for pysymex.models.stdlib.data.OperatorFloordivModel."""

    def test_faithfulness(self) -> None:
        data_models.OperatorFloordivModel().apply([4, 2], {}, _state())

    def test_error_path(self) -> None:
        data_models.OperatorFloordivModel().apply([], {}, _state())


class TestOperatorModModel:
    """Test suite for pysymex.models.stdlib.data.OperatorModModel."""

    def test_faithfulness(self) -> None:
        data_models.OperatorModModel().apply([5, 2], {}, _state())

    def test_error_path(self) -> None:
        data_models.OperatorModModel().apply([], {}, _state())


class TestOperatorNegModel:
    """Test suite for pysymex.models.stdlib.data.OperatorNegModel."""

    def test_faithfulness(self) -> None:
        data_models.OperatorNegModel().apply([-2], {}, _state())

    def test_error_path(self) -> None:
        data_models.OperatorNegModel().apply([], {}, _state())
