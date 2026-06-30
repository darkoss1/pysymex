from __future__ import annotations

import pysymex._internal.models.stdlib.dataclasses.runtime as dataclass_models
import pysymex._internal.models.stdlib.enum.models as enum_models
import pysymex._internal.models.stdlib.operator.models as operator_models
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue


def _state() -> VMState:
    return VMState(pc=0)


class TestEnumModel:
    """Test suite for pysymex._internal.models.stdlib.EnumModel."""

    def test_faithfulness(self) -> None:
        enum_models.EnumModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        enum_models.EnumModel().apply([1], {}, _state())


class TestIntEnumModel:
    """Test suite for pysymex._internal.models.stdlib.IntEnumModel."""

    def test_faithfulness(self) -> None:
        enum_models.IntEnumModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        enum_models.IntEnumModel().apply([1], {}, _state())


class TestEnumAutoModel:
    """Test suite for pysymex._internal.models.stdlib.EnumAutoModel."""

    def test_faithfulness(self) -> None:
        enum_models.EnumAutoModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        enum_models.EnumAutoModel().apply([1], {}, _state())


class TestEnumValueModel:
    """Test suite for pysymex._internal.models.stdlib.EnumValueModel."""

    def test_faithfulness(self) -> None:
        enum_models.EnumValueModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        enum_models.EnumValueModel().apply([1], {}, _state())


class TestEnumNameModel:
    """Test suite for pysymex._internal.models.stdlib.EnumNameModel."""

    def test_faithfulness(self) -> None:
        enum_models.EnumNameModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        enum_models.EnumNameModel().apply([1], {}, _state())


class TestDataclassModel:
    """Test suite for pysymex._internal.models.stdlib.DataclassModel."""

    def test_faithfulness(self) -> None:
        marker = SymbolicValue.from_const("marker")
        result = dataclass_models.DataclassModel().apply([marker], {}, _state())
        assert result.value is marker

    def test_error_path(self) -> None:
        dataclass_models.DataclassModel().apply([], {}, _state())


class TestDataclassFieldModel:
    """Test suite for pysymex._internal.models.stdlib.DataclassFieldModel."""

    def test_faithfulness(self) -> None:
        result = dataclass_models.DataclassFieldModel().apply([], {"default": 5}, _state())
        assert result.value == 5

    def test_error_path(self) -> None:
        dataclass_models.DataclassFieldModel().apply([], {}, _state())


class TestAsDataclassModel:
    """Test suite for pysymex._internal.models.stdlib.AsDataclassModel."""

    def test_faithfulness(self) -> None:
        result = dataclass_models.AsDataclassModel().apply([], {}, _state())
        assert result.value is not None

    def test_error_path(self) -> None:
        result = dataclass_models.AsDataclassModel().apply([1], {}, _state())
        assert result.value is not None


class TestAstupleModel:
    """Test suite for pysymex._internal.models.stdlib.AstupleModel."""

    def test_faithfulness(self) -> None:
        result = dataclass_models.AstupleModel().apply([], {}, _state())
        assert result.value is not None

    def test_error_path(self) -> None:
        result = dataclass_models.AstupleModel().apply([1], {}, _state())
        assert result.value is not None


class TestFieldsModel:
    """Test suite for pysymex._internal.models.stdlib.FieldsModel."""

    def test_faithfulness(self) -> None:
        result = dataclass_models.FieldsModel().apply([], {}, _state())
        assert result.value is not None

    def test_error_path(self) -> None:
        result = dataclass_models.FieldsModel().apply([1], {}, _state())
        assert result.value is not None


class TestReplaceModel:
    """Test suite for pysymex._internal.models.stdlib.ReplaceModel."""

    def test_faithfulness(self) -> None:
        result = dataclass_models.ReplaceModel().apply(
            [SymbolicValue.from_const("instance")], {"x": 1}, _state()
        )
        assert result.value is not None

    def test_error_path(self) -> None:
        dataclass_models.ReplaceModel().apply([], {}, _state())


class TestOperatorItemgetterModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorItemgetterModel."""

    def test_faithfulness(self) -> None:
        operator_models.ItemGetterModel().apply([0], {}, _state())
        operator_models.ItemGetterModel().apply([0], {}, _state())

    def test_error_path(self) -> None:
        operator_models.ItemGetterModel().apply([], {}, _state())


class TestOperatorAttrgetterModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorAttrgetterModel."""

    def test_faithfulness(self) -> None:
        operator_models.AttrGetterModel().apply(["x"], {}, _state())

    def test_error_path(self) -> None:
        operator_models.AttrGetterModel().apply([], {}, _state())


class TestOperatorAddModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorAddModel."""

    def test_faithfulness(self) -> None:
        result = operator_models.OperatorAddModel().apply([2, 3], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 5

    def test_error_path(self) -> None:
        operator_models.OperatorAddModel().apply([], {}, _state())


class TestOperatorSubModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorSubModel."""

    def test_faithfulness(self) -> None:
        result = operator_models.OperatorSubModel().apply([7, 3], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 4

    def test_error_path(self) -> None:
        operator_models.OperatorSubModel().apply([], {}, _state())


class TestOperatorMulModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorMulModel."""

    def test_faithfulness(self) -> None:
        result = operator_models.OperatorMulModel().apply([4, 3], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        assert result.value.value == 12

    def test_error_path(self) -> None:
        operator_models.OperatorMulModel().apply([], {}, _state())


class TestOperatorTruedivModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorTruedivModel."""

    def test_faithfulness(self) -> None:
        operator_models.OperatorTruedivModel().apply([4, 2], {}, _state())

    def test_error_path(self) -> None:
        operator_models.OperatorTruedivModel().apply([], {}, _state())


class TestOperatorFloordivModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorFloordivModel."""

    def test_faithfulness(self) -> None:
        operator_models.OperatorFloordivModel().apply([4, 2], {}, _state())

    def test_error_path(self) -> None:
        operator_models.OperatorFloordivModel().apply([], {}, _state())


class TestOperatorModModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorModModel."""

    def test_faithfulness(self) -> None:
        operator_models.OperatorModModel().apply([5, 2], {}, _state())

    def test_error_path(self) -> None:
        operator_models.OperatorModModel().apply([], {}, _state())


class TestOperatorNegModel:
    """Test suite for pysymex._internal.models.stdlib.OperatorNegModel."""

    def test_faithfulness(self) -> None:
        operator_models.OperatorNegModel().apply([-2], {}, _state())

    def test_error_path(self) -> None:
        operator_models.OperatorNegModel().apply([], {}, _state())
