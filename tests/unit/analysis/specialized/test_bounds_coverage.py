"""Tests for pysymex.analysis.specialized.bounds — BoundsChecker, SymbolicArray, SymbolicBuffer, ListBoundsChecker, NumpyBoundsChecker."""

from __future__ import annotations

import z3

from pysymex.analysis.specialized.bounds import (
    BoundsChecker,
    BoundsIssue,
    BoundsIssueKind,
    ListBoundsChecker,
    NumpyBoundsChecker,
    SymbolicArray,
    SymbolicBuffer,
)


class TestSymbolicArray:
    """Test SymbolicArray dataclass."""

    def test_post_init_creates_array(self) -> None:
        """Post-init creates z3 array and initializes dimensions."""
        arr = SymbolicArray(name="arr", length=z3.IntVal(10))
        assert arr.z3_array is not None
        assert len(arr.dimensions) == 1

    def test_select_reads_element(self) -> None:
        """select() returns a Z3 expression."""
        arr = SymbolicArray(name="arr", length=z3.IntVal(10))
        val = arr.select(z3.IntVal(5))
        assert isinstance(val, z3.ExprRef)

    def test_store_returns_new_array(self) -> None:
        """store() returns a new SymbolicArray with modified element."""
        arr = SymbolicArray(name="arr", length=z3.IntVal(10))
        new_arr = arr.store(z3.IntVal(3), z3.IntVal(42))
        assert isinstance(new_arr, SymbolicArray)
        assert new_arr.name == "arr'"

    def test_is_valid_index_constraint(self) -> None:
        """is_valid_index() returns correct Z3 constraint."""
        arr = SymbolicArray(name="arr", length=z3.IntVal(10))
        idx = z3.Int("idx")
        constraint = arr.is_valid_index(idx)
        s = z3.Solver()
        s.add(constraint, idx == 5)
        assert s.check() == z3.sat
        s2 = z3.Solver()
        s2.add(constraint, idx == -1)
        assert s2.check() == z3.unsat

    def test_total_size_single_dim(self) -> None:
        """total_size() returns length for 1D array."""
        arr = SymbolicArray(name="arr", length=z3.IntVal(10))
        s = z3.Solver()
        s.add(arr.total_size() == 10)
        assert s.check() == z3.sat

    def test_total_size_multi_dim(self) -> None:
        """total_size() returns product of dimensions for ND array."""
        arr = SymbolicArray(
            name="arr",
            length=z3.IntVal(6),
            dimensions=[z3.IntVal(2), z3.IntVal(3)],
        )
        s = z3.Solver()
        s.add(arr.total_size() == 6)
        assert s.check() == z3.sat


class TestSymbolicBuffer:
    """Test SymbolicBuffer dataclass."""

    def test_contains_address(self) -> None:
        """contains_address returns correct constraint."""
        buf = SymbolicBuffer(name="buf", size=z3.IntVal(100), base_address=z3.IntVal(0))
        addr = z3.Int("addr")
        constraint = buf.contains_address(addr)
        s = z3.Solver()
        s.add(constraint, addr == 50)
        assert s.check() == z3.sat
        s2 = z3.Solver()
        s2.add(constraint, addr == 100)
        assert s2.check() == z3.unsat

    def test_offset_valid(self) -> None:
        """offset_valid returns correct constraint."""
        buf = SymbolicBuffer(name="buf", size=z3.IntVal(10))
        offset = z3.Int("off")
        constraint = buf.offset_valid(offset)
        s = z3.Solver()
        s.add(constraint, offset == 5)
        assert s.check() == z3.sat


class TestBoundsChecker:
    """Test BoundsChecker methods."""

    def test_check_index_negative_oob(self) -> None:
        """check_index detects negative index out of bounds."""
        checker = BoundsChecker()
        idx = z3.Int("idx")
        length = z3.IntVal(5)
        issues = checker.check_index(idx, length, path_constraints=[idx == -10])
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.INDEX_NEGATIVE in kinds

    def test_check_index_positive_oob(self) -> None:
        """check_index detects positive index >= length."""
        checker = BoundsChecker()
        idx = z3.Int("idx")
        length = z3.IntVal(5)
        issues = checker.check_index(idx, length, path_constraints=[idx == 5])
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.INDEX_OUT_OF_BOUNDS in kinds

    def test_check_index_off_by_one(self) -> None:
        """check_index detects off-by-one (index == length)."""
        checker = BoundsChecker(check_off_by_one=True)
        idx = z3.Int("idx")
        length = z3.IntVal(5)
        issues = checker.check_index(idx, length, path_constraints=[idx == 5])
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.INDEX_EQUALS_LENGTH in kinds

    def test_check_index_no_negative_indexing(self) -> None:
        """check_index with allow_negative_indexing=False rejects any negative."""
        checker = BoundsChecker()
        idx = z3.Int("idx")
        length = z3.IntVal(5)
        issues = checker.check_index(
            idx, length, allow_negative_indexing=False, path_constraints=[idx == -1]
        )
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.INDEX_NEGATIVE in kinds

    def test_check_index_valid_no_issues(self) -> None:
        """check_index reports no issues for a constrained valid index."""
        checker = BoundsChecker(check_off_by_one=False)
        idx = z3.Int("idx")
        length = z3.IntVal(10)
        issues = checker.check_index(idx, length, path_constraints=[idx >= 0, idx < 10])
        oob = [
            i
            for i in issues
            if i.kind in {BoundsIssueKind.INDEX_NEGATIVE, BoundsIssueKind.INDEX_OUT_OF_BOUNDS}
        ]
        assert len(oob) == 0

    def test_check_slice_step_zero(self) -> None:
        """check_slice detects step == 0."""
        checker = BoundsChecker()
        length = z3.IntVal(10)
        step = z3.Int("step")
        issues = checker.check_slice(
            start=z3.IntVal(0),
            stop=z3.IntVal(5),
            step=step,
            length=length,
            path_constraints=[step == 0],
        )
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.SLICE_STEP_ZERO in kinds

    def test_check_slice_start_oob(self) -> None:
        """check_slice detects start > length."""
        checker = BoundsChecker(strict_slice_bounds=True)
        start = z3.Int("start")
        length = z3.IntVal(5)
        issues = checker.check_slice(
            start=start,
            stop=None,
            step=None,
            length=length,
            path_constraints=[start == 10],
        )
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.SLICE_START_OUT_OF_BOUNDS in kinds

    def test_check_multidim_index_dimension_mismatch(self) -> None:
        """check_multidim_index detects dimension count mismatch."""
        checker = BoundsChecker()
        issues = checker.check_multidim_index(
            indices=[z3.IntVal(0)],
            dimensions=[z3.IntVal(5), z3.IntVal(10)],
        )
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.DIMENSION_MISMATCH in kinds

    def test_check_multidim_index_valid(self) -> None:
        """check_multidim_index with matching dimensions checks each."""
        checker = BoundsChecker(check_off_by_one=False)
        issues = checker.check_multidim_index(
            indices=[z3.IntVal(1), z3.IntVal(2)],
            dimensions=[z3.IntVal(5), z3.IntVal(10)],
        )
        # 1 < 5 and 2 < 10, so no OOB
        oob = [
            i
            for i in issues
            if i.kind in {BoundsIssueKind.INDEX_NEGATIVE, BoundsIssueKind.INDEX_OUT_OF_BOUNDS}
        ]
        assert len(oob) == 0

    def test_compute_linear_index_empty(self) -> None:
        """compute_linear_index([]) returns 0."""
        checker = BoundsChecker()
        result = checker.compute_linear_index([], [])
        s = z3.Solver()
        s.add(result == 0)
        assert s.check() == z3.sat

    def test_compute_linear_index_1d(self) -> None:
        """compute_linear_index([i], [n]) returns i."""
        checker = BoundsChecker()
        result = checker.compute_linear_index([z3.IntVal(7)], [z3.IntVal(10)])
        s = z3.Solver()
        s.add(result == 7)
        assert s.check() == z3.sat

    def test_compute_linear_index_2d(self) -> None:
        """compute_linear_index([i, j], [rows, cols]) returns i*cols + j."""
        checker = BoundsChecker()
        result = checker.compute_linear_index(
            [z3.IntVal(2), z3.IntVal(3)],
            [z3.IntVal(5), z3.IntVal(10)],
        )
        s = z3.Solver()
        s.add(result == 23)  # 2*10 + 3
        assert s.check() == z3.sat

    def test_check_buffer_access_underflow(self) -> None:
        """check_buffer_access detects negative offset."""
        checker = BoundsChecker()
        buf = SymbolicBuffer(name="buf", size=z3.IntVal(100))
        offset = z3.Int("off")
        issues = checker.check_buffer_access(
            buf, offset, z3.IntVal(4), path_constraints=[offset == -1]
        )
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.BUFFER_UNDERFLOW in kinds

    def test_check_buffer_access_overflow(self) -> None:
        """check_buffer_access detects access past buffer end."""
        checker = BoundsChecker()
        buf = SymbolicBuffer(name="buf", size=z3.IntVal(10))
        offset = z3.Int("off")
        issues = checker.check_buffer_access(
            buf, offset, z3.IntVal(4), path_constraints=[offset == 8]
        )
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.BUFFER_OVERFLOW in kinds

    def test_check_memcpy_bounds_negative_size(self) -> None:
        """check_memcpy_bounds detects negative copy size."""
        checker = BoundsChecker()
        src = SymbolicBuffer(name="src", size=z3.IntVal(100))
        dst = SymbolicBuffer(name="dst", size=z3.IntVal(100))
        copy_size = z3.Int("sz")
        issues = checker.check_memcpy_bounds(
            dst,
            z3.IntVal(0),
            src,
            z3.IntVal(0),
            copy_size,
            path_constraints=[copy_size == -5],
        )
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.NEGATIVE_SIZE in kinds

    def test_check_string_index_neg_oob(self) -> None:
        """check_string_index detects negative index out of bounds."""
        checker = BoundsChecker()
        idx = z3.Int("idx")
        issues = checker.check_string_index(idx, z3.IntVal(5), path_constraints=[idx == -10])
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.STRING_INDEX_NEGATIVE in kinds

    def test_check_string_index_pos_oob(self) -> None:
        """check_string_index detects index >= length."""
        checker = BoundsChecker()
        idx = z3.Int("idx")
        issues = checker.check_string_index(idx, z3.IntVal(5), path_constraints=[idx == 5])
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.STRING_INDEX_OUT_OF_BOUNDS in kinds

    def test_check_allocation_size_negative(self) -> None:
        """check_allocation_size detects negative size."""
        checker = BoundsChecker()
        size = z3.Int("size")
        issues = checker.check_allocation_size(size, path_constraints=[size == -1])
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.NEGATIVE_SIZE in kinds

    def test_check_allocation_size_too_large(self) -> None:
        """check_allocation_size detects size > max_allowed."""
        checker = BoundsChecker()
        size = z3.Int("size")
        issues = checker.check_allocation_size(
            size, max_allowed=100, path_constraints=[size == 200]
        )
        kinds = {i.kind for i in issues}
        assert BoundsIssueKind.ALLOCATION_TOO_LARGE in kinds

    def test_check_array_access(self) -> None:
        """check_array_access returns (value, issues)."""
        checker = BoundsChecker(check_off_by_one=False)
        arr = SymbolicArray(name="arr", length=z3.IntVal(10))
        value, issues = checker.check_array_access(arr, z3.IntVal(5))
        assert isinstance(value, z3.ExprRef)

    def test_check_array_store(self) -> None:
        """check_array_store returns (new_array, issues)."""
        checker = BoundsChecker(check_off_by_one=False)
        arr = SymbolicArray(name="arr", length=z3.IntVal(10))
        new_arr, issues = checker.check_array_store(arr, z3.IntVal(3), z3.IntVal(42))
        assert isinstance(new_arr, SymbolicArray)

    def test_prove_safe_access_safe(self) -> None:
        """prove_safe_access returns (True, None) when always safe."""
        checker = BoundsChecker()
        idx = z3.Int("idx")
        length = z3.IntVal(10)
        safe, ce = checker.prove_safe_access(idx, length, path_constraints=[idx >= 0, idx < 10])
        assert safe is True
        assert ce is None

    def test_prove_safe_access_unsafe(self) -> None:
        """prove_safe_access returns (False, counterexample) when possible OOB."""
        checker = BoundsChecker()
        idx = z3.Int("idx")
        length = z3.IntVal(10)
        safe, ce = checker.prove_safe_access(idx, length)
        assert safe is False
        assert ce is not None

    def test_reset(self) -> None:
        """reset clears solver and issues."""
        checker = BoundsChecker()
        checker._issues.append(BoundsIssue(kind=BoundsIssueKind.BUFFER_OVERFLOW, message="test"))
        checker.reset()
        assert len(checker._issues) == 0

    def test_bounds_issue_format(self) -> None:
        """BoundsIssue.format() produces expected string."""
        issue = BoundsIssue(
            kind=BoundsIssueKind.INDEX_OUT_OF_BOUNDS,
            message="Index >= length",
            line_number=10,
            array_name="data",
            counterexample={"idx": 5, "len": 5},
        )
        fmt = issue.format()
        assert "INDEX_OUT_OF_BOUNDS" in fmt
        assert "line 10" in fmt
        assert "data" in fmt
        assert "idx=5" in fmt


class TestListBoundsChecker:
    """Test ListBoundsChecker."""

    def test_check_append_within_capacity(self) -> None:
        """check_append reports no issues when length < capacity."""
        checker = ListBoundsChecker()
        length = z3.IntVal(5)
        issues = checker.check_append(length, max_capacity=100)
        assert len(issues) == 0

    def test_check_append_exceeds_capacity(self) -> None:
        """check_append reports overflow when length >= capacity."""
        checker = ListBoundsChecker()
        length = z3.Int("len")
        issues = checker.check_append(length, max_capacity=10, path_constraints=[length == 10])
        assert len(issues) >= 1
        assert issues[0].kind == BoundsIssueKind.ALLOCATION_TOO_LARGE

    def test_check_extend_within_capacity(self) -> None:
        """check_extend reports no issues within capacity."""
        checker = ListBoundsChecker()
        issues = checker.check_extend(z3.IntVal(5), z3.IntVal(3), max_capacity=100)
        assert len(issues) == 0

    def test_check_extend_exceeds_capacity(self) -> None:
        """check_extend reports overflow."""
        checker = ListBoundsChecker()
        issues = checker.check_extend(z3.IntVal(8), z3.IntVal(5), max_capacity=10)
        assert len(issues) >= 1


class TestNumpyBoundsChecker:
    """Test NumpyBoundsChecker."""

    def test_check_reshape_valid(self) -> None:
        """check_reshape reports no issues for valid reshape."""
        checker = NumpyBoundsChecker()
        issues = checker.check_reshape(
            current_shape=[z3.IntVal(6)],
            new_shape=[z3.IntVal(2), z3.IntVal(3)],
        )
        assert len(issues) == 0

    def test_check_reshape_mismatch(self) -> None:
        """check_reshape detects element count mismatch."""
        checker = NumpyBoundsChecker()
        issues = checker.check_reshape(
            current_shape=[z3.IntVal(6)],
            new_shape=[z3.IntVal(2), z3.IntVal(4)],
        )
        assert len(issues) >= 1
        assert issues[0].kind == BoundsIssueKind.SHAPE_MISMATCH

    def test_check_broadcast_compatible(self) -> None:
        """check_broadcast with compatible shapes succeeds."""
        checker = NumpyBoundsChecker()
        result_shape, issues = checker.check_broadcast(
            shape1=[z3.IntVal(3), z3.IntVal(1)],
            shape2=[z3.IntVal(1), z3.IntVal(4)],
        )
        assert len(issues) == 0
        assert len(result_shape) == 2

    def test_check_broadcast_incompatible(self) -> None:
        """check_broadcast with incompatible shapes reports error."""
        checker = NumpyBoundsChecker()
        _, issues = checker.check_broadcast(
            shape1=[z3.IntVal(3)],
            shape2=[z3.IntVal(4)],
        )
        assert len(issues) >= 1
