"""Advanced Bounds Checking Analysis with Z3.
This module provides comprehensive bounds checking using Z3 SMT solver
for mathematical proofs of memory safety. Covers:
- Array/list index bounds
- Multi-dimensional array access
- Slice bounds validation
- Buffer overflow/underflow detection
- String index bounds
- Dynamic array growth bounds
"""

from __future__ import annotations


from dataclasses import dataclass, field

from enum import Enum, auto

from typing import Any, cast


import z3


from pysymex.core.solver import get_model, is_satisfiable


class BoundsIssueKind(Enum):
    """Types of bounds checking issues."""

    INDEX_NEGATIVE = auto()

    INDEX_OUT_OF_BOUNDS = auto()

    INDEX_EQUALS_LENGTH = auto()

    SLICE_START_NEGATIVE = auto()

    SLICE_START_OUT_OF_BOUNDS = auto()

    SLICE_STOP_NEGATIVE = auto()

    SLICE_STOP_OUT_OF_BOUNDS = auto()

    SLICE_STEP_ZERO = auto()

    SLICE_INVALID_RANGE = auto()

    BUFFER_OVERFLOW = auto()

    BUFFER_UNDERFLOW = auto()

    HEAP_OVERFLOW = auto()

    STACK_OVERFLOW = auto()

    DIMENSION_MISMATCH = auto()

    SHAPE_MISMATCH = auto()

    STRING_INDEX_NEGATIVE = auto()

    STRING_INDEX_OUT_OF_BOUNDS = auto()

    ENCODING_BOUNDS = auto()

    ALLOCATION_TOO_LARGE = auto()

    NEGATIVE_SIZE = auto()


@dataclass
class BoundsIssue:
    """Represents a detected bounds checking issue."""

    kind: BoundsIssueKind

    message: str

    location: str | None = None

    line_number: int | None = None

    constraints: list[Any] = field(default_factory=list[Any])

    counterexample: dict[str, Any] = field(default_factory=dict[str, Any])

    severity: str = "error"

    array_name: str | None = None

    index_expr: str | None = None

    def format(self) -> str:
        """Format issue for display."""

        loc = f" at line {self.line_number}" if self.line_number else ""

        arr = f" on {self.array_name}" if self.array_name else ""

        ce = ""

        if self.counterexample:
            ce = " | Counterexample: " + ", ".join(
                f"{k}={v}" for k, v in self.counterexample.items()
            )

        return f"[{self.kind.name}]{loc}{arr}: {self.message}{ce}"


@dataclass
class SymbolicArray:
    """
    Symbolic representation of an array with Z3.
    Supports:
    - Fixed or symbolic length
    - Multi-dimensional arrays
    - Element type constraints
    """

    name: str

    length: z3.ArithRef

    element_sort: z3.SortRef = field(default_factory=lambda: z3.IntSort())

    dimensions: list[z3.ArithRef] = field(default_factory=list[z3.ArithRef])

    _array: z3.ArrayRef | None = None

    def __post_init__(self):
        if not self.dimensions:
            self.dimensions = [self.length]

        if self._array is None:
            self._array = z3.Array(self.name, z3.IntSort(), self.element_sort)

    @property
    def z3_array(self) -> z3.ArrayRef:
        """Get the underlying Z3 array."""

        assert self._array is not None

        return self._array

    def select(self, index: z3.ArithRef) -> z3.ExprRef:
        """Read element at index."""

        assert self._array is not None

        return z3.Select(self._array, index)

    def store(self, index: z3.ArithRef, value: z3.ExprRef) -> SymbolicArray:
        """Write element at index, return new array."""

        assert self._array is not None

        new_array = z3.Store(self._array, index, value)

        return SymbolicArray(
            name=f"{self.name}'",
            length=self.length,
            element_sort=self.element_sort,
            dimensions=self.dimensions,
            _array=new_array,
        )

    def is_valid_index(self, index: z3.ArithRef) -> z3.BoolRef:
        """Generate constraint that index is valid."""

        return z3.And(index >= 0, index < self.length)

    def total_size(self) -> z3.ArithRef:
        """Get total number of elements (product of dimensions)."""

        if len(self.dimensions) == 1:
            return self.length

        result = self.dimensions[0]

        for dim in self.dimensions[1:]:
            result = result * dim

        return result


@dataclass
class SymbolicBuffer:
    """
    Symbolic representation of a raw memory buffer.
    For lower-level buffer overflow analysis.
    """

    name: str

    size: z3.ArithRef

    base_address: z3.ArithRef = field(default_factory=lambda: z3.Int("base_0"))

    def contains_address(self, addr: z3.ArithRef) -> z3.BoolRef:
        """Check if address is within buffer bounds."""

        return z3.And(addr >= self.base_address, addr < self.base_address + self.size)

    def offset_valid(self, offset: z3.ArithRef) -> z3.BoolRef:
        """Check if offset from base is valid."""

        return z3.And(offset >= 0, offset < self.size)


class BoundsChecker:
    """
    Comprehensive bounds checking analyzer using Z3.
    Provides mathematically proven detection of out-of-bounds access
    for arrays, lists, strings, and raw buffers.
    """

    def __init__(
        self,
        timeout_ms: int = 5000,
        check_off_by_one: bool = True,
        strict_slice_bounds: bool = True,
    ):
        self.timeout_ms = timeout_ms

        self.check_off_by_one = check_off_by_one

        self.strict_slice_bounds = strict_slice_bounds

        self._solver = z3.Solver()

        self._solver.set("timeout", timeout_ms)

        self._issues: list[BoundsIssue] = []

    def reset(self) -> None:
        """Reset checker state."""

        self._solver.reset()

        self._issues.clear()

    def check_index(
        self,
        index: z3.ArithRef,
        length: z3.ArithRef,
        array_name: str = "array",
        path_constraints: list[z3.BoolRef] | None = None,
        allow_negative_indexing: bool = True,
    ) -> list[BoundsIssue]:
        """
        Check if array index is within bounds.
        Args:
            index: Symbolic index expression
            length: Symbolic or concrete array length
            array_name: Name for error messages
            path_constraints: Current path constraints
            allow_negative_indexing: Whether Python-style negative indices are allowed
        Returns:
            List of bounds issues found
        """

        issues: list[BoundsIssue] = []

        constraints = list(path_constraints or [])

        if allow_negative_indexing:
            neg_oob = z3.And(index < 0, index < -length)

            if is_satisfiable(constraints + [neg_oob]):
                model = get_model(constraints + [neg_oob])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.INDEX_NEGATIVE,
                        message="Negative index too small for array length",
                        array_name=array_name,
                        index_expr=str(index),
                        constraints=constraints + [neg_oob],
                        counterexample=self._extract_model(model, [index, length]),
                    )
                )

            pos_oob = z3.And(index >= 0, index >= length)

            if is_satisfiable(constraints + [pos_oob]):
                model = get_model(constraints + [pos_oob])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.INDEX_OUT_OF_BOUNDS,
                        message="Index >= length",
                        array_name=array_name,
                        index_expr=str(index),
                        constraints=constraints + [pos_oob],
                        counterexample=self._extract_model(model, [index, length]),
                    )
                )

        else:
            negative = index < 0

            if is_satisfiable(constraints + [negative]):
                model = get_model(constraints + [negative])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.INDEX_NEGATIVE,
                        message="Negative index not allowed",
                        array_name=array_name,
                        index_expr=str(index),
                        constraints=constraints + [negative],
                        counterexample=self._extract_model(model, [index, length]),
                    )
                )

            too_large = index >= length

            if is_satisfiable(constraints + [too_large]):
                model = get_model(constraints + [too_large])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.INDEX_OUT_OF_BOUNDS,
                        message="Index >= length",
                        array_name=array_name,
                        index_expr=str(index),
                        constraints=constraints + [too_large],
                        counterexample=self._extract_model(model, [index, length]),
                    )
                )

        if self.check_off_by_one:
            off_by_one = index == length

            if is_satisfiable(constraints + [off_by_one]):
                model = get_model(constraints + [off_by_one])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.INDEX_EQUALS_LENGTH,
                        message="Off-by-one: index equals length",
                        array_name=array_name,
                        index_expr=str(index),
                        constraints=constraints + [off_by_one],
                        counterexample=self._extract_model(model, [index, length]),
                        severity="warning",
                    )
                )

        return issues

    def check_slice(
        self,
        start: z3.ArithRef | None,
        stop: z3.ArithRef | None,
        step: z3.ArithRef | None,
        length: z3.ArithRef,
        array_name: str = "array",
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """
        Check if slice bounds are valid.
        Args:
            start: Slice start (None means 0 or length-1 for negative step)
            stop: Slice stop (None means length or -1 for negative step)
            step: Slice step (None means 1)
            length: Array length
            array_name: Name for error messages
            path_constraints: Current path constraints
        Returns:
            List of bounds issues found
        """

        issues: list[BoundsIssue] = []

        constraints = list(path_constraints or [])

        if step is None:
            step = z3.IntVal(1)

        step_zero = step == 0

        if is_satisfiable(constraints + [step_zero]):
            model = get_model(constraints + [step_zero])

            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.SLICE_STEP_ZERO,
                    message="Slice step cannot be zero",
                    array_name=array_name,
                    constraints=constraints + [step_zero],
                    counterexample=self._extract_model(model, [step]),
                )
            )

        if start is not None and self.strict_slice_bounds:
            start_neg_oob = z3.And(start < 0, start < -length)

            if is_satisfiable(constraints + [start_neg_oob]):
                model = get_model(constraints + [start_neg_oob])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.SLICE_START_NEGATIVE,
                        message="Slice start negative index too small",
                        array_name=array_name,
                        constraints=constraints + [start_neg_oob],
                        counterexample=self._extract_model(model, [start, length]),
                    )
                )

            start_pos_oob = z3.And(start >= 0, start > length)

            if is_satisfiable(constraints + [start_pos_oob]):
                model = get_model(constraints + [start_pos_oob])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.SLICE_START_OUT_OF_BOUNDS,
                        message="Slice start > length",
                        array_name=array_name,
                        constraints=constraints + [start_pos_oob],
                        counterexample=self._extract_model(model, [start, length]),
                    )
                )

        if stop is not None and self.strict_slice_bounds:
            stop_neg_oob = z3.And(stop < 0, stop < -length)

            if is_satisfiable(constraints + [stop_neg_oob]):
                model = get_model(constraints + [stop_neg_oob])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.SLICE_STOP_NEGATIVE,
                        message="Slice stop negative index too small",
                        array_name=array_name,
                        constraints=constraints + [stop_neg_oob],
                        counterexample=self._extract_model(model, [stop, length]),
                    )
                )

            stop_pos_oob = z3.And(stop >= 0, stop > length)

            if is_satisfiable(constraints + [stop_pos_oob]):
                model = get_model(constraints + [stop_pos_oob])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.SLICE_STOP_OUT_OF_BOUNDS,
                        message="Slice stop > length",
                        array_name=array_name,
                        constraints=constraints + [stop_pos_oob],
                        counterexample=self._extract_model(model, [stop, length]),
                    )
                )

        return issues

    def check_multidim_index(
        self,
        indices: list[z3.ArithRef],
        dimensions: list[z3.ArithRef],
        array_name: str = "array",
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """
        Check bounds for multi-dimensional array access.
        E.g., array[i][j][k] with shape (dim0, dim1, dim2)
        """

        issues: list[BoundsIssue] = []

        constraints = list(path_constraints or [])

        if len(indices) != len(dimensions):
            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.DIMENSION_MISMATCH,
                    message=f"Expected {len(dimensions)} indices, got {len(indices)}",
                    array_name=array_name,
                )
            )

            return issues

        for i, (idx, dim) in enumerate(zip(indices, dimensions, strict=False)):
            dim_issues = self.check_index(
                idx,
                dim,
                array_name=f"{array_name}[dim{i}]",
                path_constraints=constraints,
                allow_negative_indexing=True,
            )

            issues.extend(dim_issues)

        return issues

    def compute_linear_index(
        self,
        indices: list[z3.ArithRef],
        dimensions: list[z3.ArithRef],
    ) -> z3.ArithRef:
        """
        Compute linear index for multi-dimensional array.
        For row-major order: index = i * (dim1 * dim2) + j * dim2 + k
        """

        if len(indices) == 0:
            return z3.IntVal(0)

        if len(indices) == 1:
            return indices[0]

        strides: list[z3.ArithRef] = []

        stride: z3.ArithRef = z3.IntVal(1)

        for dim in reversed(dimensions[1:]):
            strides.insert(0, stride)

            stride = stride * dim

        strides.insert(0, stride)

        linear: z3.ArithRef = z3.IntVal(0)

        for idx, s in zip(indices, strides, strict=False):
            linear = linear + idx * s

        return linear

    def check_buffer_access(
        self,
        buffer: SymbolicBuffer,
        offset: z3.ArithRef,
        access_size: z3.ArithRef,
        is_write: bool = False,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """
        Check if buffer access is within bounds.
        Args:
            buffer: Symbolic buffer being accessed
            offset: Offset from buffer start
            access_size: Size of access (e.g., 4 bytes for int)
            is_write: Whether this is a write operation
            path_constraints: Current path constraints
        Returns:
            List of bounds issues found
        """

        issues: list[BoundsIssue] = []

        constraints = list(path_constraints or [])

        underflow = offset < 0

        if is_satisfiable(constraints + [underflow]):
            model = get_model(constraints + [underflow])

            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.BUFFER_UNDERFLOW,
                    message="Buffer underflow: negative offset",
                    array_name=buffer.name,
                    constraints=constraints + [underflow],
                    counterexample=self._extract_model(model, [offset, buffer.size]),
                )
            )

        overflow = offset + access_size > buffer.size

        if is_satisfiable(constraints + [overflow]):
            model = get_model(constraints + [overflow])

            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.BUFFER_OVERFLOW,
                    message="Buffer overflow: access extends past end",
                    array_name=buffer.name,
                    constraints=constraints + [overflow],
                    counterexample=self._extract_model(model, [offset, access_size, buffer.size]),
                )
            )

        return issues

    def check_memcpy_bounds(
        self,
        dest: SymbolicBuffer,
        dest_offset: z3.ArithRef,
        src: SymbolicBuffer,
        src_offset: z3.ArithRef,
        copy_size: z3.ArithRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """
        Check bounds for memory copy operation.
        Validates both source and destination buffers.
        """

        issues: list[BoundsIssue] = []

        constraints = list(path_constraints or [])

        src_issues = self.check_buffer_access(
            src, src_offset, copy_size, is_write=False, path_constraints=constraints
        )

        issues.extend(src_issues)

        dest_issues = self.check_buffer_access(
            dest, dest_offset, copy_size, is_write=True, path_constraints=constraints
        )

        issues.extend(dest_issues)

        neg_size = copy_size < 0

        if is_satisfiable(constraints + [neg_size]):
            model = get_model(constraints + [neg_size])

            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.NEGATIVE_SIZE,
                    message="Negative copy size",
                    constraints=constraints + [neg_size],
                    counterexample=self._extract_model(model, [copy_size]),
                )
            )

        return issues

    def check_string_index(
        self,
        index: z3.ArithRef,
        str_length: z3.ArithRef,
        string_name: str = "string",
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """
        Check string index bounds.
        Similar to array but with string-specific issue kinds.
        """

        issues: list[BoundsIssue] = []

        constraints = list(path_constraints or [])

        neg_oob = z3.And(index < 0, index < -str_length)

        if is_satisfiable(constraints + [neg_oob]):
            model = get_model(constraints + [neg_oob])

            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.STRING_INDEX_NEGATIVE,
                    message="String negative index out of bounds",
                    array_name=string_name,
                    constraints=constraints + [neg_oob],
                    counterexample=self._extract_model(model, [index, str_length]),
                )
            )

        pos_oob = z3.And(index >= 0, index >= str_length)

        if is_satisfiable(constraints + [pos_oob]):
            model = get_model(constraints + [pos_oob])

            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.STRING_INDEX_OUT_OF_BOUNDS,
                    message="String index >= length",
                    array_name=string_name,
                    constraints=constraints + [pos_oob],
                    counterexample=self._extract_model(model, [index, str_length]),
                )
            )

        return issues

    def check_allocation_size(
        self,
        size: z3.ArithRef,
        max_allowed: int = 2**30,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """
        Check if allocation size is reasonable.
        Detects:
        - Negative sizes
        - Excessively large allocations
        """

        issues: list[BoundsIssue] = []

        constraints = list(path_constraints or [])

        neg_size = size < 0

        if is_satisfiable(constraints + [neg_size]):
            model = get_model(constraints + [neg_size])

            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.NEGATIVE_SIZE,
                    message="Negative allocation size",
                    constraints=constraints + [neg_size],
                    counterexample=self._extract_model(model, [size]),
                )
            )

        too_large = size > max_allowed

        if is_satisfiable(constraints + [too_large]):
            model = get_model(constraints + [too_large])

            issues.append(
                BoundsIssue(
                    kind=BoundsIssueKind.ALLOCATION_TOO_LARGE,
                    message=f"Allocation size > {max_allowed}",
                    constraints=constraints + [too_large],
                    counterexample=self._extract_model(model, [size]),
                )
            )

        return issues

    def check_array_access(
        self,
        array: SymbolicArray,
        index: z3.ArithRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[z3.ExprRef, list[BoundsIssue]]:
        """
        Check array access and return (value, issues).
        Returns a guarded value that defaults to a symbolic "undefined"
        if the index is out of bounds.
        """

        issues = self.check_index(
            index,
            array.length,
            array_name=array.name,
            path_constraints=path_constraints,
        )

        value = array.select(index)

        return (value, issues)

    def check_array_store(
        self,
        array: SymbolicArray,
        index: z3.ArithRef,
        value: z3.ExprRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[SymbolicArray, list[BoundsIssue]]:
        """
        Check array store and return (new_array, issues).
        """

        issues = self.check_index(
            index,
            array.length,
            array_name=array.name,
            path_constraints=path_constraints,
        )

        new_array = array.store(index, value)

        return (new_array, issues)

    def prove_safe_access(
        self,
        index: z3.ArithRef,
        length: z3.ArithRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, str | None]:
        """
        Prove that an index is always safe under given constraints.
        Returns:
            (is_provably_safe, counterexample_if_not)
        """

        constraints = list(path_constraints or [])

        oob_possible = z3.Or(index < 0, index >= length)

        if is_satisfiable(constraints + [oob_possible]):
            model = get_model(constraints + [oob_possible])

            ce = self._extract_model(model, [index, length])

            return (False, f"Counterexample: {ce}")

        else:
            return (True, None)

    def _extract_model(
        self,
        model: z3.ModelRef | None,
        vars: list[z3.ExprRef],
    ) -> dict[str, Any]:
        """Extract variable values from Z3 model."""

        if model is None:
            return {}

        result: dict[str, Any] = {}

        for var in vars:
            try:
                val = model.eval(var, model_completion=True)

                if z3.is_int_value(val):
                    result[str(var)] = val.as_long()

                elif z3.is_rational_value(val):
                    result[str(var)] = float(val.as_fraction())

                else:
                    result[str(var)] = str(val)

            except Exception:
                pass

        return result


class ListBoundsChecker(BoundsChecker):
    """Specialized bounds checker for Python lists."""

    def check_append(
        self,
        current_length: z3.ArithRef,
        max_capacity: int = 2**30,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """Check if list append could exceed capacity."""

        constraints = list(path_constraints or [])

        overflow = current_length >= max_capacity

        if is_satisfiable(constraints + [overflow]):
            model = get_model(constraints + [overflow])

            return [
                BoundsIssue(
                    kind=BoundsIssueKind.ALLOCATION_TOO_LARGE,
                    message="List append would exceed max capacity",
                    constraints=constraints + [overflow],
                    counterexample=self._extract_model(model, [current_length]),
                )
            ]

        return []

    def check_extend(
        self,
        current_length: z3.ArithRef,
        extend_length: z3.ArithRef,
        max_capacity: int = 2**30,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """Check if list extend could overflow."""

        constraints = list(path_constraints or [])

        new_length = current_length + extend_length

        overflow = new_length > max_capacity

        if is_satisfiable(constraints + [overflow]):
            model = get_model(constraints + [overflow])

            return [
                BoundsIssue(
                    kind=BoundsIssueKind.ALLOCATION_TOO_LARGE,
                    message="List extend would exceed max capacity",
                    constraints=constraints + [overflow],
                    counterexample=self._extract_model(model, [current_length, extend_length]),
                )
            ]

        return []


class NumpyBoundsChecker(BoundsChecker):
    """Specialized bounds checker for NumPy-style arrays."""

    def check_reshape(
        self,
        current_shape: list[z3.ArithRef],
        new_shape: list[z3.ArithRef],
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[BoundsIssue]:
        """Check if reshape is valid (same total elements)."""

        constraints = list(path_constraints or [])

        current_total = z3.IntVal(1)

        for dim in current_shape:
            current_total = current_total * dim

        new_total = z3.IntVal(1)

        for dim in new_shape:
            new_total = new_total * dim

        mismatch = current_total != new_total

        if is_satisfiable(constraints + [mismatch]):
            model = get_model(constraints + [mismatch])

            return [
                BoundsIssue(
                    kind=BoundsIssueKind.SHAPE_MISMATCH,
                    message="Reshape total elements mismatch",
                    constraints=constraints + [mismatch],
                    counterexample=self._extract_model(
                        model, cast(list[z3.ExprRef], current_shape + new_shape)
                    ),
                )
            ]

        return []

    def check_broadcast(
        self,
        shape1: list[z3.ArithRef],
        shape2: list[z3.ArithRef],
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[list[z3.ArithRef], list[BoundsIssue]]:
        """
        Check if two shapes can be broadcast together.
        Returns (result_shape, issues).
        """

        issues: list[BoundsIssue] = []

        constraints = list(path_constraints or [])

        max_dims = max(len(shape1), len(shape2))

        padded1 = [z3.IntVal(1)] * (max_dims - len(shape1)) + list(shape1)

        padded2 = [z3.IntVal(1)] * (max_dims - len(shape2)) + list(shape2)

        result_shape: list[z3.ArithRef] = []

        for d1, d2 in zip(padded1, padded2, strict=False):
            incompatible = z3.And(d1 != d2, d1 != 1, d2 != 1)

            if is_satisfiable(constraints + [incompatible]):
                model = get_model(constraints + [incompatible])

                issues.append(
                    BoundsIssue(
                        kind=BoundsIssueKind.SHAPE_MISMATCH,
                        message="Shapes cannot be broadcast together",
                        constraints=constraints + [incompatible],
                        counterexample=self._extract_model(model, [d1, d2]),
                    )
                )

            result_shape.append(z3.If(d1 > d2, d1, d2))

        return (result_shape, issues)


__all__ = [
    "BoundsIssueKind",
    "BoundsIssue",
    "SymbolicArray",
    "SymbolicBuffer",
    "BoundsChecker",
    "ListBoundsChecker",
    "NumpyBoundsChecker",
]
