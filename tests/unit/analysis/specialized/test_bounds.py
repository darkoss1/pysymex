import pytest
import z3
from unittest.mock import Mock, patch
from pysymex.analysis.specialized.bounds import (
    BoundsIssueKind,
    BoundsIssue,
    SymbolicArray,
    SymbolicBuffer,
    BoundsChecker,
    ListBoundsChecker,
    NumpyBoundsChecker,
)


class TestBoundsIssueKind:
    """Test suite for pysymex.analysis.specialized.bounds.BoundsIssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert BoundsIssueKind.INDEX_OUT_OF_BOUNDS.name == "INDEX_OUT_OF_BOUNDS"
        assert BoundsIssueKind.BUFFER_OVERFLOW.name == "BUFFER_OVERFLOW"


class TestBoundsIssue:
    """Test suite for pysymex.analysis.specialized.bounds.BoundsIssue."""

    def test_format(self) -> None:
        """Test format behavior."""
        issue = BoundsIssue(
            kind=BoundsIssueKind.INDEX_OUT_OF_BOUNDS,
            message="Out of bounds",
            array_name="arr",
            line_number=10,
        )
        fmt = issue.format()
        assert "[INDEX_OUT_OF_BOUNDS] at line 10 on arr: Out of bounds" in fmt


class TestSymbolicArray:
    """Test suite for pysymex.analysis.specialized.bounds.SymbolicArray."""

    def test_z3_array(self) -> None:
        """Test z3_array behavior."""
        arr = SymbolicArray("arr", z3.IntVal(10), z3.IntSort())
        assert isinstance(arr.z3_array, z3.ArrayRef)

    def test_select(self) -> None:
        """Test select behavior."""
        arr = SymbolicArray("arr", z3.IntVal(10), z3.IntSort())
        res = arr.select(z3.IntVal(0))
        assert isinstance(res, z3.ArithRef)

    def test_store(self) -> None:
        """Test store behavior."""
        arr = SymbolicArray("arr", z3.IntVal(10), z3.IntSort())
        new_arr = arr.store(z3.IntVal(0), z3.IntVal(42))
        assert isinstance(new_arr, SymbolicArray)

    def test_is_valid_index(self) -> None:
        """Test is_valid_index behavior."""
        arr = SymbolicArray("arr", z3.IntVal(10), z3.IntSort())
        cond = arr.is_valid_index(z3.IntVal(5))
        assert z3.simplify(cond)

    def test_total_size(self) -> None:
        """Test total_size behavior."""
        arr = SymbolicArray("arr", z3.IntVal(10), z3.IntSort())
        assert z3.is_true(z3.simplify(arr.total_size() == z3.IntVal(10)))


class TestSymbolicBuffer:
    """Test suite for pysymex.analysis.specialized.bounds.SymbolicBuffer."""

    def test_contains_address(self) -> None:
        """Test contains_address behavior."""
        buf = SymbolicBuffer("buf", z3.IntVal(100), z3.IntVal(0))
        cond = buf.contains_address(z3.IntVal(50))
        assert z3.is_true(z3.simplify(cond))

    def test_offset_valid(self) -> None:
        """Test offset_valid behavior."""
        buf = SymbolicBuffer("buf", z3.IntVal(100), z3.IntVal(0))
        cond = buf.offset_valid(z3.IntVal(10))
        assert z3.is_true(z3.simplify(cond))


class TestBoundsChecker:
    """Test suite for pysymex.analysis.specialized.bounds.BoundsChecker."""

    def test_reset(self) -> None:
        """Test reset behavior."""
        c = BoundsChecker()
        c._issues.append(Mock())
        c.reset()
        assert len(c._issues) == 0

    def test_check_index(self) -> None:
        """Test check_index behavior."""
        c = BoundsChecker()
        arr = SymbolicArray("arr", z3.IntVal(5), z3.IntSort())
        issues = c.check_index(z3.IntVal(10), arr.length, array_name=arr.name)
        assert len(issues) > 0
        assert issues[0].kind == BoundsIssueKind.INDEX_OUT_OF_BOUNDS

        issues_safe = c.check_index(z3.IntVal(2), arr.length, array_name=arr.name)
        assert len(issues_safe) == 0

    def test_check_slice(self) -> None:
        """Test check_slice behavior."""
        c = BoundsChecker()
        arr = SymbolicArray("arr", z3.IntVal(5), z3.IntSort())
        issues = c.check_slice(
            z3.IntVal(0), z3.IntVal(10), z3.IntVal(1), arr.length, array_name=arr.name
        )
        assert len(issues) > 0

    def test_check_multidim_index(self) -> None:
        """Test check_multidim_index behavior."""
        c = BoundsChecker()
        arr = SymbolicArray(
            "arr", z3.IntVal(25), z3.IntSort(), dimensions=[z3.IntVal(5), z3.IntVal(5)]
        )
        issues = c.check_multidim_index(
            [z3.IntVal(0), z3.IntVal(10)], arr.dimensions, array_name=arr.name
        )
        assert len(issues) > 0

    def test_compute_linear_index(self) -> None:
        """Test compute_linear_index behavior."""
        c = BoundsChecker()
        idx = c.compute_linear_index([z3.IntVal(1), z3.IntVal(2)], [z3.IntVal(5), z3.IntVal(5)])
        assert z3.is_true(z3.simplify(idx == z3.IntVal(7)))

    def test_check_buffer_access(self) -> None:
        """Test check_buffer_access behavior."""
        c = BoundsChecker()
        buf = SymbolicBuffer("buf", z3.IntVal(100), z3.IntVal(0))
        issues = c.check_buffer_access(buf, z3.IntVal(98), z3.IntVal(4))
        assert len(issues) > 0
        assert issues[0].kind == BoundsIssueKind.BUFFER_OVERFLOW

    def test_check_memcpy_bounds(self) -> None:
        """Test check_memcpy_bounds behavior."""
        c = BoundsChecker()
        src = SymbolicBuffer("src", z3.IntVal(50), z3.IntVal(0))
        dst = SymbolicBuffer("dst", z3.IntVal(50), z3.IntVal(100))
        issues = c.check_memcpy_bounds(src, z3.IntVal(0), dst, z3.IntVal(100), z3.IntVal(60))
        assert len(issues) > 0

    def test_check_string_index(self) -> None:
        """Test check_string_index behavior."""
        c = BoundsChecker()
        issues = c.check_string_index(z3.IntVal(10), z3.IntVal(5), "my_str")
        assert len(issues) > 0

    def test_check_allocation_size(self) -> None:
        """Test check_allocation_size behavior."""
        c = BoundsChecker()
        issues = c.check_allocation_size(z3.IntVal(-1))
        assert len(issues) > 0
        assert issues[0].kind == BoundsIssueKind.NEGATIVE_SIZE

    def test_check_array_access(self) -> None:
        """Test check_array_access behavior."""
        c = BoundsChecker()
        arr = SymbolicArray("arr", z3.IntVal(5), z3.IntSort())
        res, issues = c.check_array_access(arr, z3.IntVal(10))
        assert len(issues) > 0

    def test_check_array_store(self) -> None:
        """Test check_array_store behavior."""
        c = BoundsChecker()
        arr = SymbolicArray("arr", z3.IntVal(5), z3.IntSort())
        res, issues = c.check_array_store(arr, z3.IntVal(10), z3.IntVal(42))
        assert len(issues) > 0

    @patch("pysymex.analysis.specialized.bounds.z3.Solver.check", return_value=z3.unsat)
    def test_prove_safe_access(self, mock_check) -> None:
        """Test prove_safe_access behavior."""
        c = BoundsChecker()
        safe, msg = c.prove_safe_access(z3.IntVal(2), z3.IntVal(5))
        assert safe is True


class TestListBoundsChecker:
    """Test suite for pysymex.analysis.specialized.bounds.ListBoundsChecker."""

    def test_check_append(self) -> None:
        """Test check_append behavior."""
        c = ListBoundsChecker()
        arr = SymbolicArray("arr", z3.IntVal(5), z3.IntSort())
        issues = c.check_append(arr.length)
        assert len(issues) == 0

    def test_check_extend(self) -> None:
        """Test check_extend behavior."""
        c = ListBoundsChecker()
        arr = SymbolicArray("arr", z3.IntVal(5), z3.IntSort())
        other = SymbolicArray("other", z3.IntVal(2), z3.IntSort())
        issues = c.check_extend(arr.length, other.length)
        assert len(issues) == 0


class TestNumpyBoundsChecker:
    """Test suite for pysymex.analysis.specialized.bounds.NumpyBoundsChecker."""

    def test_check_reshape(self) -> None:
        """Test check_reshape behavior."""
        c = NumpyBoundsChecker()
        arr = SymbolicArray(
            "arr", z3.IntVal(6), z3.IntSort(), dimensions=[z3.IntVal(2), z3.IntVal(3)]
        )
        issues = c.check_reshape(arr.dimensions, [z3.IntVal(6)])
        assert len(issues) == 0

        issues_bad = c.check_reshape(arr.dimensions, [z3.IntVal(5)])
        assert len(issues_bad) > 0

    def test_check_broadcast(self) -> None:
        """Test check_broadcast behavior."""
        c = NumpyBoundsChecker()
        arr1 = SymbolicArray("arr1", z3.IntVal(3), z3.IntSort(), dimensions=[z3.IntVal(3)])
        arr2 = SymbolicArray(
            "arr2", z3.IntVal(6), z3.IntSort(), dimensions=[z3.IntVal(2), z3.IntVal(3)]
        )
        shape, issues = c.check_broadcast(arr1.dimensions, arr2.dimensions)
        assert len(issues) == 0


0
0
0
