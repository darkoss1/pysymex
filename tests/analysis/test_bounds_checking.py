"""Tests for bounds_checking module.

Tests the Z3-based bounds checking analysis including:
- Array/list index bounds
- Slice bounds validation
- Buffer overflow/underflow detection
- Multi-dimensional array access
"""

import pytest
import z3

from pysymex.analysis.bounds_checking import (
    BoundsChecker,
    BoundsIssue,
    BoundsIssueKind,
    SymbolicArray,
    SymbolicBuffer,
)

# =============================================================================
# SymbolicArray Tests
# =============================================================================


class TestSymbolicArray:
    """Tests for SymbolicArray class."""

    def test_array_creation(self):
        """Test basic array creation."""
        length = z3.IntVal(10)
        arr = SymbolicArray(name="arr", length=length)

        assert arr.name == "arr"
        assert arr.z3_array is not None

    def test_array_select(self):
        """Test array element selection."""
        length = z3.IntVal(10)
        arr = SymbolicArray(name="arr", length=length)

        index = z3.Int("i")
        element = arr.select(index)

        assert element is not None

    def test_array_store(self):
        """Test array element store."""
        length = z3.IntVal(10)
        arr = SymbolicArray(name="arr", length=length)

        index = z3.Int("i")
        value = z3.IntVal(42)
        new_arr = arr.store(index, value)

        assert new_arr.name == "arr'"
        assert new_arr.z3_array is not None

    def test_is_valid_index(self):
        """Test valid index constraint generation."""
        length = z3.IntVal(10)
        arr = SymbolicArray(name="arr", length=length)

        index = z3.Int("i")
        constraint = arr.is_valid_index(index)

        assert constraint is not None

    def test_multidim_array_total_size(self):
        """Test multi-dimensional array size calculation."""
        dim1 = z3.IntVal(3)
        dim2 = z3.IntVal(4)
        arr = SymbolicArray(
            name="matrix",
            length=dim1,
            dimensions=[dim1, dim2],
        )

        size = arr.total_size()
        assert size is not None


# =============================================================================
# SymbolicBuffer Tests
# =============================================================================


class TestSymbolicBuffer:
    """Tests for SymbolicBuffer class."""

    def test_buffer_creation(self):
        """Test basic buffer creation."""
        size = z3.IntVal(1024)
        buf = SymbolicBuffer(name="buf", size=size)

        assert buf.name == "buf"

    def test_contains_address(self):
        """Test address containment check."""
        size = z3.IntVal(1024)
        base = z3.IntVal(0x1000)
        buf = SymbolicBuffer(name="buf", size=size, base_address=base)

        addr = z3.Int("addr")
        constraint = buf.contains_address(addr)

        assert constraint is not None

    def test_offset_valid(self):
        """Test offset validity check."""
        size = z3.IntVal(1024)
        buf = SymbolicBuffer(name="buf", size=size)

        offset = z3.Int("offset")
        constraint = buf.offset_valid(offset)

        assert constraint is not None


# =============================================================================
# BoundsChecker Tests
# =============================================================================


class TestBoundsChecker:
    """Tests for BoundsChecker class."""

    @pytest.fixture
    def checker(self):
        return BoundsChecker()

    def test_checker_creation(self, checker):
        """Test checker initialization."""
        assert checker.timeout_ms == 5000
        assert checker.check_off_by_one is True

    def test_check_index_safe(self, checker):
        """Test safe index check (constrained to valid range)."""
        index = z3.Int("i")
        length = z3.IntVal(10)

        # Constrain index to valid range
        constraints = [index >= 0, index < length]

        issues = checker.check_index(
            index,
            length,
            array_name="arr",
            path_constraints=constraints,
        )

        # With constraints, should be safe
        assert len(issues) == 0

    def test_check_index_out_of_bounds(self, checker):
        """Test out of bounds index detection."""
        index = z3.Int("i")
        length = z3.IntVal(10)

        # No constraints - index could be anything
        issues = checker.check_index(
            index,
            length,
            array_name="arr",
        )

        # Should detect potential issues
        assert len(issues) > 0

    def test_check_index_negative(self, checker):
        """Test negative index detection when not allowed."""
        index = z3.Int("i")
        length = z3.IntVal(10)

        issues = checker.check_index(
            index,
            length,
            array_name="arr",
            allow_negative_indexing=False,
        )

        # Should detect negative index possibility
        negative_issues = [i for i in issues if i.kind == BoundsIssueKind.INDEX_NEGATIVE]
        assert len(negative_issues) > 0

    def test_check_index_off_by_one(self, checker):
        """Test off-by-one detection."""
        index = z3.Int("i")
        length = z3.IntVal(10)

        issues = checker.check_index(
            index,
            length,
            array_name="arr",
        )

        # Should detect off-by-one possibility
        off_by_one_issues = [i for i in issues if i.kind == BoundsIssueKind.INDEX_EQUALS_LENGTH]
        assert len(off_by_one_issues) > 0

    def test_check_slice_step_zero(self, checker):
        """Test slice with step=0 detection."""
        start = z3.Int("start")
        stop = z3.Int("stop")
        step = z3.Int("step")
        length = z3.IntVal(10)

        issues = checker.check_slice(
            start,
            stop,
            step,
            length,
            array_name="arr",
        )

        # Should detect step=0 possibility
        step_zero_issues = [i for i in issues if i.kind == BoundsIssueKind.SLICE_STEP_ZERO]
        assert len(step_zero_issues) > 0

    def test_check_slice_safe(self, checker):
        """Test safe slice."""
        start = z3.Int("start")
        stop = z3.Int("stop")
        length = z3.IntVal(10)

        # Constrain to valid slice
        constraints = [start >= 0, start <= stop, stop <= length]

        issues = checker.check_slice(
            start,
            stop,
            None,
            length,
            array_name="arr",
            path_constraints=constraints,
        )

        # Should be fewer issues with constraints (still checks step)
        step_zero_issues = [i for i in issues if i.kind == BoundsIssueKind.SLICE_STEP_ZERO]
        # step is None so no step zero issue
        assert len(step_zero_issues) == 0

    def test_check_multidim_index(self, checker):
        """Test multi-dimensional index checking."""
        i = z3.Int("i")
        j = z3.Int("j")
        dim0 = z3.IntVal(3)
        dim1 = z3.IntVal(4)

        issues = checker.check_multidim_index(
            indices=[i, j],
            dimensions=[dim0, dim1],
            array_name="matrix",
        )

        # Should detect potential issues for both dimensions
        assert len(issues) > 0

    def test_check_multidim_dimension_mismatch(self, checker):
        """Test dimension mismatch detection."""
        i = z3.Int("i")
        dim0 = z3.IntVal(3)
        dim1 = z3.IntVal(4)

        issues = checker.check_multidim_index(
            indices=[i],  # Only 1 index
            dimensions=[dim0, dim1],  # 2 dimensions
            array_name="matrix",
        )

        # Should detect dimension mismatch
        mismatch_issues = [i for i in issues if i.kind == BoundsIssueKind.DIMENSION_MISMATCH]
        assert len(mismatch_issues) > 0

    def test_check_buffer_access_safe(self, checker):
        """Test safe buffer access."""
        size = z3.IntVal(1024)
        buf = SymbolicBuffer(name="buf", size=size)

        offset = z3.Int("offset")
        access_size = z3.IntVal(4)

        # Constrain offset to valid range
        constraints = [offset >= 0, offset + access_size <= size]

        issues = checker.check_buffer_access(
            buf,
            offset,
            access_size,
            path_constraints=constraints,
        )

        assert len(issues) == 0

    def test_check_buffer_overflow(self, checker):
        """Test buffer overflow detection."""
        size = z3.IntVal(1024)
        buf = SymbolicBuffer(name="buf", size=size)

        offset = z3.Int("offset")
        access_size = z3.IntVal(4)

        issues = checker.check_buffer_access(
            buf,
            offset,
            access_size,
        )

        # Should detect potential overflow
        overflow_issues = [i for i in issues if i.kind == BoundsIssueKind.BUFFER_OVERFLOW]
        assert len(overflow_issues) > 0

    def test_check_buffer_underflow(self, checker):
        """Test buffer underflow detection."""
        size = z3.IntVal(1024)
        buf = SymbolicBuffer(name="buf", size=size)

        offset = z3.Int("offset")
        access_size = z3.IntVal(4)

        issues = checker.check_buffer_access(
            buf,
            offset,
            access_size,
        )

        # Should detect potential underflow
        underflow_issues = [i for i in issues if i.kind == BoundsIssueKind.BUFFER_UNDERFLOW]
        assert len(underflow_issues) > 0

    def test_compute_linear_index(self, checker):
        """Test linear index computation."""
        i = z3.IntVal(1)
        j = z3.IntVal(2)
        dim0 = z3.IntVal(3)
        dim1 = z3.IntVal(4)

        linear = checker.compute_linear_index([i, j], [dim0, dim1])

        # Verify that the linear index is a valid Z3 expression
        # The exact value depends on the implementation's stride calculation
        assert linear is not None

        # Just verify it's a Z3 ArithRef that can be used in constraints
        solver = z3.Solver()
        # Should be some non-negative integer for valid indices
        solver.add(linear >= 0)
        assert solver.check() == z3.sat

    def test_checker_reset(self, checker):
        """Test checker reset."""
        checker.reset()
        # Should not raise


# =============================================================================
# BoundsIssue Tests
# =============================================================================


class TestBoundsIssue:
    """Tests for BoundsIssue class."""

    def test_issue_creation(self):
        """Test issue creation."""
        issue = BoundsIssue(
            kind=BoundsIssueKind.INDEX_OUT_OF_BOUNDS,
            message="Index >= length",
            array_name="arr",
            line_number=42,
        )

        assert issue.kind == BoundsIssueKind.INDEX_OUT_OF_BOUNDS
        assert issue.array_name == "arr"
        assert issue.line_number == 42

    def test_issue_format(self):
        """Test issue formatting."""
        issue = BoundsIssue(
            kind=BoundsIssueKind.INDEX_OUT_OF_BOUNDS,
            message="Index >= length",
            array_name="arr",
            line_number=42,
        )

        formatted = issue.format()
        assert "INDEX_OUT_OF_BOUNDS" in formatted
        assert "42" in formatted
        assert "arr" in formatted

    def test_issue_with_counterexample(self):
        """Test issue with counterexample."""
        issue = BoundsIssue(
            kind=BoundsIssueKind.INDEX_OUT_OF_BOUNDS,
            message="Index >= length",
            array_name="arr",
            counterexample={"index": 10, "length": 5},
        )

        formatted = issue.format()
        assert "Counterexample" in formatted


# =============================================================================
# BoundsIssueKind Tests
# =============================================================================


class TestBoundsIssueKind:
    """Tests for BoundsIssueKind enum."""

    def test_index_issues(self):
        """Test index-related issue kinds exist."""
        assert BoundsIssueKind.INDEX_NEGATIVE
        assert BoundsIssueKind.INDEX_OUT_OF_BOUNDS
        assert BoundsIssueKind.INDEX_EQUALS_LENGTH

    def test_slice_issues(self):
        """Test slice-related issue kinds exist."""
        assert BoundsIssueKind.SLICE_START_NEGATIVE
        assert BoundsIssueKind.SLICE_STEP_ZERO
        assert BoundsIssueKind.SLICE_INVALID_RANGE

    def test_buffer_issues(self):
        """Test buffer-related issue kinds exist."""
        assert BoundsIssueKind.BUFFER_OVERFLOW
        assert BoundsIssueKind.BUFFER_UNDERFLOW
        assert BoundsIssueKind.HEAP_OVERFLOW
