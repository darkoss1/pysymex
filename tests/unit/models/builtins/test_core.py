from __future__ import annotations

import pytest
import z3

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.core.types.containers import SymbolicList
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.models.builtins import core


def _state() -> VMState:
    return VMState(pc=0)


class TestLenModel:
    """Test suite for pysymex.models.builtins.core.LenModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        with pytest.raises(NameError):
            core.LenModel().apply([], {}, _state())


class TestRangeModel:
    """Test suite for pysymex.models.builtins.core.RangeModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        args: list[StackValue] = [3]
        result = core.RangeModel().apply(args, {}, _state())
        assert result.value is not None

    def test_apply_unrolls_small_bounded_ranges(self) -> None:
        """Test small concrete ranges avoid quantified constraints."""
        result = core.RangeModel().apply([1, 4], {}, _state())
        assert result.value is not None
        assert not any(z3.is_quantifier(constraint) for constraint in result.constraints)


class TestAbsModel:
    """Test suite for pysymex.models.builtins.core.AbsModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        value = -5
        assert core.AbsModel().apply([value], {}, _state()).value == abs(value)


class TestMinModel:
    """Test suite for pysymex.models.builtins.core.MinModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        values: list[StackValue] = [4, 1, 6]
        assert core.MinModel().apply(values, {}, _state()).value == 1


class TestMaxModel:
    """Test suite for pysymex.models.builtins.core.MaxModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        values: list[StackValue] = [4, 1, 6]
        assert core.MaxModel().apply(values, {}, _state()).value == 6


class TestIntModel:
    """Test suite for pysymex.models.builtins.core.IntModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        value = "12"
        assert core.IntModel().apply([value], {}, _state()).value == int(value)


class TestStrModel:
    """Test suite for pysymex.models.builtins.core.StrModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        value = 12
        assert core.StrModel().apply([value], {}, _state()).value == str(value)


class TestBoolModel:
    """Test suite for pysymex.models.builtins.core.BoolModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        value = 0
        assert core.BoolModel().apply([value], {}, _state()).value == bool(value)


class TestPrintModel:
    """Test suite for pysymex.models.builtins.core.PrintModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        result = core.PrintModel().apply(["x"], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestTypeModel:
    """Test suite for pysymex.models.builtins.core.TypeModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        assert core.TypeModel().apply([], {}, _state()).value is type


class TestIsinstanceModel:
    """Test suite for pysymex.models.builtins.core.IsinstanceModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        result = core.IsinstanceModel().apply([], {}, _state())
        assert result.value is False


class TestSortedModel:
    """Test suite for pysymex.models.builtins.core.SortedModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        result = core.SortedModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestSumModel:
    """Test suite for pysymex.models.builtins.core.SumModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        values: list[StackValue] = [1, 2, 3]
        args: list[StackValue] = [values]
        assert core.SumModel().apply(args, {}, _state()).value == 6


class TestEnumerateModel:
    """Test suite for pysymex.models.builtins.core.EnumerateModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        iterable: list[StackValue] = [1, 2]
        args: list[StackValue] = [iterable]
        result = core.EnumerateModel().apply(args, {}, _state())
        assert result.value is not None


class TestZipModel:
    """Test suite for pysymex.models.builtins.core.ZipModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        first: list[StackValue] = [1]
        second: list[StackValue] = [2]
        args: list[StackValue] = [first, second]
        result = core.ZipModel().apply(args, {}, _state())
        assert result.value is not None


class TestMapModel:
    """Test suite for pysymex.models.builtins.core.MapModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        iterable: list[StackValue] = [1]
        args: list[StackValue] = [str, iterable]
        result = core.MapModel().apply(args, {}, _state())
        assert result.value is not None


class TestFilterModel:
    """Test suite for pysymex.models.builtins.core.FilterModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        iterable: list[StackValue] = [0, 1]
        args: list[StackValue] = [bool, iterable]
        result = core.FilterModel().apply(args, {}, _state())
        assert result.value is not None


class TestFloatModel:
    """Test suite for pysymex.models.builtins.core.FloatModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        result = core.FloatModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicValue)


class TestListModel:
    """Test suite for pysymex.models.builtins.core.ListModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        values: list[StackValue] = [1, 2]
        args: list[StackValue] = [values]
        with pytest.raises(NameError):
            core.ListModel().apply(args, {}, _state())


class TestTupleModel:
    """Test suite for pysymex.models.builtins.core.TupleModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        value: list[StackValue] = [1, 2]
        args: list[StackValue] = [value]
        assert core.TupleModel().apply(args, {}, _state()).value == tuple(value)


class TestNoneModel:
    """Test suite for pysymex.models.builtins.core.NoneModel."""
    def test_apply(self) -> None:
        """Test apply behavior."""
        result = core.NoneModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


def test_core_model_edge_paths() -> None:
    """Exercise edge and error-adjacent model paths with valid stack values."""
    abs_args: list[StackValue] = [-1]
    int_args: list[StackValue] = ["7"]
    str_args: list[StackValue] = [7]
    bool_args: list[StackValue] = [1]
    sum_items: list[StackValue] = [1, 2]
    sum_args: list[StackValue] = [sum_items]

    assert core.AbsModel().apply(abs_args, {}, _state()).value == 1
    assert core.IntModel().apply(int_args, {}, _state()).value == 7
    assert core.StrModel().apply(str_args, {}, _state()).value == "7"
    assert core.BoolModel().apply(bool_args, {}, _state()).value is True
    assert core.SumModel().apply(sum_args, {}, _state()).value == 3
