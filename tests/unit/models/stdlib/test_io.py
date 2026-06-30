from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.models.stdlib.bisect.models import (
    BisectLeftModel,
    BisectModel,
    BisectRightModel,
    InsortLeftModel,
    InsortModel,
    InsortRightModel,
)
from pysymex._internal.models.stdlib.copy.models import CopyModel, DeepcopyModel
from pysymex._internal.models.stdlib.heapq.models import (
    HeapifyModel,
    HeappopModel,
    HeappushModel,
    HeappushpopModel,
    HeapreplaceModel,
    NlargestModel,
    NsmallestModel,
)
from pysymex._internal.models.stdlib.io.models import (
    BytesIOModel,
    IOGetvalueModel,
    IOReadModel,
    IOWriteModel,
    StringIOModel,
)
from pysymex._internal.models.stdlib.registry import get_stdlib_model


def _state() -> VMState:
    return VMState(pc=0)


class TestCopyModel:
    """Test suite for pysymex._internal.models.stdlib.CopyModel."""

    def test_faithfulness(self) -> None:
        result = CopyModel().apply([7], {}, _state())
        assert result.value == 7

    def test_error_path(self) -> None:
        CopyModel().apply([], {}, _state())


class TestDeepcopyModel:
    """Test suite for pysymex._internal.models.stdlib.DeepcopyModel."""

    def test_faithfulness(self) -> None:
        DeepcopyModel().apply([1], {}, _state())

    def test_error_path(self) -> None:
        DeepcopyModel().apply([], {}, _state())


class TestStringIOModel:
    """Test suite for pysymex._internal.models.stdlib.StringIOModel."""

    def test_faithfulness(self) -> None:
        StringIOModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        StringIOModel().apply(["x"], {}, _state())


class TestBytesIOModel:
    """Test suite for pysymex._internal.models.stdlib.BytesIOModel."""

    def test_faithfulness(self) -> None:
        BytesIOModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        BytesIOModel().apply([b"x"], {}, _state())


class TestIOReadModel:
    """Test suite for pysymex._internal.models.stdlib.IOReadModel."""

    def test_faithfulness(self) -> None:
        IOReadModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        IOReadModel().apply([1], {}, _state())

    def test_file_read_alias_resolves_to_io_read_model(self) -> None:
        assert isinstance(get_stdlib_model("file.read"), IOReadModel)


class TestIOWriteModel:
    """Test suite for pysymex._internal.models.stdlib.IOWriteModel."""

    def test_faithfulness(self) -> None:
        sym = SymbolicString.from_const("abc")
        result = IOWriteModel().apply([sym], {}, _state())
        assert isinstance(result.value, SymbolicValue)

    def test_error_path(self) -> None:
        IOWriteModel().apply([], {}, _state())

    def test_file_write_alias_resolves_to_io_write_model(self) -> None:
        assert isinstance(get_stdlib_model("file.write"), IOWriteModel)


class TestIOGetvalueModel:
    """Test suite for pysymex._internal.models.stdlib.IOGetvalueModel."""

    def test_faithfulness(self) -> None:
        IOGetvalueModel().apply([], {}, _state())

    def test_error_path(self) -> None:
        IOGetvalueModel().apply([1], {}, _state())


class TestHeappushModel:
    """Test suite for pysymex._internal.models.stdlib.HeappushModel."""

    def test_faithfulness(self) -> None:
        result = HeappushModel().apply([[], 1], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = HeappushModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_symbolic_heap_tracks_added_item(self) -> None:
        heap = SymbolicList.empty("heap")
        result = HeappushModel().apply([heap, SymbolicValue.from_const(7)], {}, _state())
        mutation = cast("dict[str, object]", result.side_effects["list_mutation"])
        updated = cast("SymbolicList", mutation["updated_list"])
        assert simplify_expr(updated.z3_len).as_long() == 1


class TestHeappopModel:
    """Test suite for pysymex._internal.models.stdlib.HeappopModel."""

    def test_faithfulness(self) -> None:
        HeappopModel().apply([[]], {}, _state())

    def test_error_path(self) -> None:
        HeappopModel().apply([], {}, _state())

    def test_symbolic_heap_reports_index_error_and_removes_item(self) -> None:
        heap = SymbolicList.from_const([7])
        result = HeappopModel().apply([heap], {}, _state())
        effect = result.side_effects.get("potential_exception")
        assert SideEffects.is_potential_exception(effect)
        assert effect["type"] == "IndexError"
        assert effect["message"] == "index out of range"
        mutation = cast("dict[str, object]", result.side_effects["list_mutation"])
        updated = cast("SymbolicList", mutation["updated_list"])
        assert simplify_expr(updated.z3_len).as_long() == 0


class TestHeapifyModel:
    """Test suite for pysymex._internal.models.stdlib.HeapifyModel."""

    def test_faithfulness(self) -> None:
        result = HeapifyModel().apply([[]], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = HeapifyModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestHeapreplaceModel:
    """Test suite for pysymex._internal.models.stdlib.HeapreplaceModel."""

    def test_faithfulness(self) -> None:
        HeapreplaceModel().apply([[1], 2], {}, _state())

    def test_error_path(self) -> None:
        HeapreplaceModel().apply([], {}, _state())


class TestHeappushpopModel:
    """Test suite for pysymex._internal.models.stdlib.HeappushpopModel."""

    def test_faithfulness(self) -> None:
        HeappushpopModel().apply([[1], 2], {}, _state())

    def test_error_path(self) -> None:
        HeappushpopModel().apply([], {}, _state())


class TestNlargestModel:
    """Test suite for pysymex._internal.models.stdlib.NlargestModel."""

    def test_faithfulness(self) -> None:
        result = NlargestModel().apply([2, [1, 2, 3]], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = NlargestModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestNsmallestModel:
    """Test suite for pysymex._internal.models.stdlib.NsmallestModel."""

    def test_faithfulness(self) -> None:
        result = NsmallestModel().apply([2, [1, 2, 3]], {}, _state())
        assert isinstance(result.value, SymbolicList)

    def test_error_path(self) -> None:
        result = NsmallestModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicList)


class TestBisectLeftModel:
    """Test suite for pysymex._internal.models.stdlib.BisectLeftModel."""

    def test_faithfulness(self) -> None:
        BisectLeftModel().apply([[1, 2, 3], 2], {}, _state())

    def test_error_path(self) -> None:
        BisectLeftModel().apply([], {}, _state())

    def test_concrete_integer_list_links_end_position_to_needle(self) -> None:
        values = SymbolicList.from_const([10, 20, 30])
        needle, type_constraint = SymbolicValue.symbolic_int("needle")
        result = BisectLeftModel().apply([values, needle], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(type_constraint, *result.constraints, needle.z3_int == 31)
        solver.add(result.value.z3_int != 3)
        assert solver.check() == z3.unsat


class TestBisectRightModel:
    """Test suite for pysymex._internal.models.stdlib.BisectRightModel."""

    def test_faithfulness(self) -> None:
        BisectRightModel().apply([[1, 2, 3], 2], {}, _state())

    def test_error_path(self) -> None:
        BisectRightModel().apply([], {}, _state())

    def test_concrete_integer_list_places_equal_value_after_existing_entry(self) -> None:
        values = SymbolicList.from_const([10, 20, 30])
        needle, type_constraint = SymbolicValue.symbolic_int("needle")
        result = BisectRightModel().apply([values, needle], {}, _state())
        assert isinstance(result.value, SymbolicValue)
        solver = z3.Solver()
        solver.add(type_constraint, *result.constraints, needle.z3_int == 20)
        solver.add(result.value.z3_int != 2)
        assert solver.check() == z3.unsat


class TestBisectModel:
    """Test suite for pysymex._internal.models.stdlib.BisectModel."""

    def test_faithfulness(self) -> None:
        BisectModel().apply([[1, 2, 3], 2], {}, _state())

    def test_error_path(self) -> None:
        BisectModel().apply([], {}, _state())


class TestInsortLeftModel:
    """Test suite for pysymex._internal.models.stdlib.InsortLeftModel."""

    def test_faithfulness(self) -> None:
        result = InsortLeftModel().apply([[1, 2], 3], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = InsortLeftModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestInsortRightModel:
    """Test suite for pysymex._internal.models.stdlib.InsortRightModel."""

    def test_faithfulness(self) -> None:
        result = InsortRightModel().apply([[1, 2], 3], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = InsortRightModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)


class TestInsortModel:
    """Test suite for pysymex._internal.models.stdlib.InsortModel."""

    def test_faithfulness(self) -> None:
        result = InsortModel().apply([[1, 2], 3], {}, _state())
        assert isinstance(result.value, SymbolicNone)

    def test_error_path(self) -> None:
        result = InsortModel().apply([], {}, _state())
        assert isinstance(result.value, SymbolicNone)
