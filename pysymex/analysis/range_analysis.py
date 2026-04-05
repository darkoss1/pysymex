# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Value Range Analysis for pysymex.
This module provides value range analysis to track the possible
ranges of numeric values through program execution. This helps
detect bugs like:
- Array index out of bounds
- Integer overflow
- Division by zero
- Invalid ranges in loops
"""

from __future__ import annotations

import logging

import icontract

logger = logging.getLogger(__name__)

import dis
import types
from collections import defaultdict
from dataclasses import dataclass, field

from pysymex._compat import get_starts_line

from .flow_sensitive import BasicBlock, CFGBuilder, ControlFlowGraph


def _union_postcondition(self: Range, other: Range, result: Range) -> bool:
    return self.subset_of(result) and other.subset_of(result)


def _intersect_postcondition(self: Range, other: Range, result: Range) -> bool:
    return result.subset_of(self) or result.is_empty


@dataclass(frozen=True)
class Range:
    """
    Represents a range of integer values [low, high].
    """

    low: int | None = None
    high: int | None = None
    is_empty: bool = False
    is_numeric: bool = False

    @classmethod
    def empty(cls) -> Range:
        """Create empty range (bottom)."""
        return cls(is_empty=True)

    @classmethod
    def full(cls) -> Range:
        """Create full range (top)."""
        return cls(None, None)

    @classmethod
    def exact(cls, value: int) -> Range:
        """Create singleton range."""
        return cls(value, value, is_numeric=True)

    @classmethod
    def at_least(cls, min_val: int) -> Range:
        """Create range [min_val, +infinity)."""
        return cls(min_val, None)

    @classmethod
    def at_most(cls, max_val: int) -> Range:
        """Create range (-infinity, max_val]."""
        return cls(None, max_val)

    @classmethod
    def between(cls, low: int, high: int) -> Range:
        """Create range [low, high]."""
        if low > high:
            return cls.empty()
        return cls(low, high)

    def is_full(self) -> bool:
        """Check if this is the full range."""
        return not self.is_empty and self.low is None and self.high is None

    @property
    def is_exact(self) -> bool:
        """Check if this is a singleton."""
        return (
            not self.is_empty
            and self.low is not None
            and self.high is not None
            and self.low == self.high
        )

    @property
    def exact_value(self) -> int | None:
        """Get exact value if singleton."""
        if self.is_exact:
            return self.low
        return None

    def contains(self, value: int) -> bool:
        """Check if value is in range."""
        if self.is_empty:
            return False
        if self.low is not None and value < self.low:
            return False
        if self.high is not None and value > self.high:
            return False
        return True

    def may_be_zero(self) -> bool:
        """Check if range may contain zero."""
        return self.contains(0)

    def must_be_positive(self) -> bool:
        """Check if all values in range are positive."""
        return not self.is_empty and self.low is not None and self.low > 0

    def must_be_negative(self) -> bool:
        """Check if all values in range are negative."""
        return not self.is_empty and self.high is not None and self.high < 0

    def must_be_non_negative(self) -> bool:
        """Check if all values are >= 0."""
        return not self.is_empty and self.low is not None and self.low >= 0

    def must_be_non_positive(self) -> bool:
        """Check if all values are <= 0."""
        return not self.is_empty and self.high is not None and self.high <= 0

    def must_be_non_zero(self) -> bool:
        """Check if zero is definitely not in range."""
        if self.is_empty:
            return True
        return not self.contains(0)

    @icontract.ensure(_union_postcondition)
    def union(self, other: Range) -> Range:
        """Compute union (join) of two ranges."""
        if self.is_empty:
            return other
        if other.is_empty:
            return self
        new_low: int | None
        new_high: int | None
        if self.low is None or other.low is None:
            new_low = None
        else:
            new_low = min(self.low, other.low)
        if self.high is None or other.high is None:
            new_high = None
        else:
            new_high = max(self.high, other.high)
        return Range(new_low, new_high)

    @icontract.ensure(_intersect_postcondition)
    def intersect(self, other: Range) -> Range:
        """Compute intersection (meet) of two ranges."""
        if self.is_empty or other.is_empty:
            return Range.empty()
        new_low: int | None
        new_high: int | None
        if self.low is None:
            new_low = other.low
        elif other.low is None:
            new_low = self.low
        else:
            new_low = max(self.low, other.low)
        if self.high is None:
            new_high = other.high
        elif other.high is None:
            new_high = self.high
        else:
            new_high = min(self.high, other.high)
        if new_low is not None and new_high is not None and new_low > new_high:
            return Range.empty()
        return Range(new_low, new_high)

    def widen(self, other: Range) -> Range:
        """Standard widening for loop analysis."""
        if self.is_empty:
            return other
        if other.is_empty:
            return self
        new_low: int | None
        new_high: int | None
        if other.low is not None:
            if self.low is None or other.low < self.low:
                new_low = None
            else:
                new_low = self.low
        else:
            new_low = None
        if other.high is not None:
            if self.high is None or other.high > self.high:
                new_high = None
            else:
                new_high = self.high
        else:
            new_high = None
        return Range(new_low, new_high)

    def narrow(self, other: Range) -> Range:
        """Standard narrowing."""
        new_low = self.low if self.low is not None else other.low
        new_high = self.high if self.high is not None else other.high
        return Range(new_low, new_high)

    def subset_of(self, other: Range) -> bool:
        """Check if this range is a subset of other."""
        if self.is_empty:
            return True
        if other.is_empty:
            return False
        if other.low is not None:
            if self.low is None or self.low < other.low:
                return False
        if other.high is not None:
            if self.high is None or self.high > other.high:
                return False
        return True

    def add(self, other: Range) -> Range:
        """Range addition."""
        if self.is_empty or other.is_empty:
            return Range.empty()
        new_low: int | None = None
        new_high: int | None = None
        if self.low is not None and other.low is not None:
            new_low = self.low + other.low
        if self.high is not None and other.high is not None:
            new_high = self.high + other.high
        return Range(new_low, new_high)

    def sub(self, other: Range) -> Range:
        """Range subtraction."""
        if self.is_empty or other.is_empty:
            return Range.empty()
        new_low: int | None = None
        new_high: int | None = None
        if self.low is not None and other.high is not None:
            new_low = self.low - other.high
        if self.high is not None and other.low is not None:
            new_high = self.high - other.low
        return Range(new_low, new_high)

    def neg(self) -> Range:
        """Range negation."""
        if self.is_empty:
            return Range.empty()
        new_low = -self.high if self.high is not None else None
        new_high = -self.low if self.low is not None else None
        return Range(new_low, new_high)

    def mul(self, other: Range) -> Range:
        """Range multiplication."""
        if self.is_empty or other.is_empty:
            return Range.empty()
        if self.is_exact and other.is_exact:
            assert self.low is not None and other.low is not None
            return Range.exact(self.low * other.low)
        if self.is_full() or other.is_full():
            return Range.full()
        if (
            self.low is not None
            and self.high is not None
            and other.low is not None
            and other.high is not None
        ):
            products = [
                self.low * other.low,
                self.low * other.high,
                self.high * other.low,
                self.high * other.high,
            ]
            return Range(min(products), max(products))
        return Range.full()

    def div(self, other: Range) -> tuple[Range, bool]:
        """Range division. Returns (result, may_div_by_zero)."""
        if self.is_empty or other.is_empty:
            return Range.empty(), False
        may_div_by_zero = other.contains(0)
        if other.is_exact and other.low == 0:
            return Range.empty(), True
        if other.is_exact and other.low is not None and other.low != 0:
            divisor = other.low
            if self.is_exact:
                assert self.low is not None
                return Range.exact(self.low // divisor), False
            if self.low is not None and self.high is not None:
                results = [self.low // divisor, self.high // divisor]
                return Range(min(results), max(results)), False
        return Range.full(), may_div_by_zero

    def mod(self, other: Range) -> tuple[Range, bool]:
        """Range modulo. Returns (result, may_div_by_zero)."""
        if self.is_empty or other.is_empty:
            return Range.empty(), False
        may_div_by_zero = other.contains(0)
        if other.is_exact and other.low == 0:
            return Range.empty(), True
        if other.is_exact and other.low is not None and other.low > 0:
            m = other.low
            return Range(0, m - 1), False
        return Range.full(), may_div_by_zero

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        if self.is_empty:
            return "∅"
        low_str = str(self.low) if self.low is not None else "-∞"
        high_str = str(self.high) if self.high is not None else "+∞"
        return f"[{low_str}, {high_str}]"


def _pop_precondition(self: RangeState) -> bool:
    return not self.is_bottom


@dataclass
class RangeState:
    """State for range analysis."""

    variables: dict[str, Range] = field(default_factory=dict[str, Range])
    stack: list[Range] = field(default_factory=list[Range])
    is_bottom: bool = False

    @classmethod
    def bottom(cls) -> RangeState:
        return cls(is_bottom=True)

    @classmethod
    def top(cls) -> RangeState:
        return cls()

    def copy(self) -> RangeState:
        """Copy."""
        if self.is_bottom:
            return RangeState.bottom()
        return RangeState(
            variables=dict(self.variables),
            stack=list(self.stack),
        )

    def get(self, var: str) -> Range:
        return self.variables.get(var, Range.full())

    def set(self, var: str, range_val: Range) -> None:
        self.variables[var] = range_val

    def push(self, range_val: Range) -> None:
        self.stack.append(range_val)

    @icontract.require(_pop_precondition)
    def pop(self) -> Range:
        """Pop."""
        if self.stack:
            return self.stack.pop()
        return Range.full()

    def peek(self, depth: int = 0) -> Range:
        """Peek."""
        idx = -(depth + 1)
        if abs(idx) <= len(self.stack):
            return self.stack[idx]
        return Range.full()

    def join(self, other: RangeState) -> RangeState:
        """Join."""
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        result = RangeState()
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            r1 = self.get(var)
            r2 = other.get(var)
            result.variables[var] = r1.union(r2)
        return result

    def widen(self, other: RangeState) -> RangeState:
        """Widen."""
        if self.is_bottom:
            return other.copy()
        if other.is_bottom:
            return self.copy()
        result = RangeState()
        all_vars = set(self.variables.keys()) | set(other.variables.keys())
        for var in all_vars:
            r1 = self.get(var)
            r2 = other.get(var)
            result.variables[var] = r1.widen(r2)
        return result

    def subset_of(self, other: RangeState) -> bool:
        """Check if self ⊆ other (every variable range in self fits within other)."""
        if self.is_bottom:
            return True
        if other.is_bottom:
            return False
        for var, range_val in self.variables.items():
            if not range_val.subset_of(other.get(var)):
                return False
        for var in other.variables:
            if var not in self.variables:
                if not Range.full().subset_of(other.get(var)):
                    return False
        return True


@dataclass(frozen=True, slots=True)
class RangeWarning:
    """A warning from range analysis."""

    line: int
    pc: int
    kind: str
    message: str
    range_info: Range | None = None


class RangeAnalyzer:
    """
    Performs value range analysis on bytecode.
    """

    def analyze(
        self,
        code: types.CodeType,
        file_path: str = "<unknown>",
    ) -> tuple[dict[str, Range], list[RangeWarning]]:
        """Analyze function for range information."""
        builder = CFGBuilder()
        cfg = builder.build(code)
        final_ranges, warnings = self._analyze_cfg(cfg, code, file_path)
        return final_ranges, warnings

    def _analyze_cfg(
        self,
        cfg: ControlFlowGraph,
        code: types.CodeType,
        file_path: str,
    ) -> tuple[dict[str, Range], list[RangeWarning]]:
        """Run range analysis on CFG."""
        all_warnings: list[RangeWarning] = []
        states: dict[int, RangeState] = {}

        pc_to_line: dict[int, int] = {}
        try:
            last_line = code.co_firstlineno

            line_list = list(code.co_lines())
            if line_list:
                for start, end, line in line_list:
                    if line is not None:
                        last_line = line
                    for pc in range(start, end):
                        pc_to_line[pc] = last_line

            for block in cfg.blocks.values():
                for instr in block.instructions:
                    if instr.offset not in pc_to_line:
                        pc_to_line[instr.offset] = last_line
        except (AttributeError, Exception):
            logger.warning(
                "CFG construction failed during range analysis, falling back", exc_info=True
            )

        if cfg.entry:
            initial = RangeState()
            for arg in code.co_varnames[: code.co_argcount]:
                initial.set(arg, Range.full())
            states[cfg.entry.block_id] = initial
        worklist = [cfg.entry] if cfg.entry else []
        iterations: dict[int, int] = defaultdict(int)
        global_iters = 0
        max_global_iters = len(cfg.blocks) * 10 + 100
        while worklist and global_iters < max_global_iters:
            global_iters += 1
            block = worklist.pop(0)
            if not block:
                continue
            in_state = states.get(block.block_id, RangeState.bottom())
            if in_state.is_bottom:
                continue
            out_state, block_warnings = self._transfer_block(
                block,
                in_state,
                code,
                file_path,
                pc_to_line=pc_to_line,
            )
            all_warnings.extend(block_warnings)
            for succ_id in block.successors:
                old_state = states.get(succ_id, RangeState.bottom())
                iterations[succ_id] += 1
                if iterations[succ_id] > 3:
                    new_state = old_state.widen(out_state)
                else:
                    new_state = old_state.join(out_state)
                if not new_state.subset_of(old_state):
                    states[succ_id] = new_state
                    succ_block = cfg.blocks.get(succ_id)
                    if succ_block is not None and succ_block not in worklist:
                        worklist.append(succ_block)
        if worklist and global_iters >= max_global_iters:
            logger.warning(
                "Range analysis hit iteration limit (%d) — results may be unsound",
                max_global_iters,
            )
        final: dict[str, Range] = {}
        for state in states.values():
            for var, range_val in state.variables.items():
                if var in final:
                    final[var] = final[var].union(range_val)
                else:
                    final[var] = range_val
        return final, all_warnings

    def _transfer_block(
        self,
        block: BasicBlock,
        in_state: RangeState,
        code: types.CodeType,
        file_path: str,
        pc_to_line: dict[int, int] | None = None,
    ) -> tuple[RangeState, list[RangeWarning]]:
        """Transfer function for a block."""
        state = in_state.copy()
        block_warnings: list[RangeWarning] = []
        current_line = 0
        if block.instructions and pc_to_line:
            current_line = pc_to_line.get(block.instructions[0].offset, 0)

        for instr in block.instructions:
            if pc_to_line and instr.offset in pc_to_line:
                current_line = pc_to_line[instr.offset]
            else:
                line = get_starts_line(instr)
                if line is not None:
                    current_line = line
                break
        for instr in block.instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            instr_warnings = self._transfer_instruction(
                instr,
                state,
                current_line,
                file_path,
            )
            block_warnings.extend(instr_warnings)
        return state, block_warnings

    def _transfer_instruction(
        self,
        instr: dis.Instruction,
        state: RangeState,
        line: int,
        file_path: str,
    ) -> list[RangeWarning]:
        """Transfer function for an instruction.

        Mutates *state* in place (caller owns the copy) and returns any
        warnings produced by this instruction.
        """
        warnings: list[RangeWarning] = []
        opname = instr.opname
        arg = instr.argval
        if opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            state.push(state.get(arg))
        elif opname == "LOAD_CONST":
            if isinstance(arg, int):
                state.push(Range.exact(arg))
            elif isinstance(arg, (float, complex)):
                state.push(Range(None, None, is_numeric=True))
            else:
                state.push(Range(None, None, is_numeric=False))
        elif opname in {"STORE_FAST", "STORE_NAME", "STORE_GLOBAL", "STORE_DEREF"}:
            if state.stack:
                state.set(arg, state.pop())
        elif opname == "BINARY_OP":
            if len(state.stack) >= 2:
                right = state.pop()
                left = state.pop()
                op_name = instr.argrepr or ""
                if "+" in op_name:
                    state.push(left.add(right))
                elif "-" in op_name:
                    state.push(left.sub(right))
                elif "*" in op_name and "**" not in op_name:
                    state.push(left.mul(right))
                elif "//" in op_name or "/" in op_name:
                    result, may_div_zero = left.div(right)
                    if (
                        may_div_zero
                        and not right.must_be_non_zero()
                        and right.is_numeric
                        and left.is_numeric
                    ):
                        warnings.append(
                            RangeWarning(
                                line=line,
                                pc=instr.offset,
                                kind="DIVISION_BY_ZERO",
                                message=f"Possible division by zero (divisor range: {right})",
                                range_info=right,
                            )
                        )
                    state.push(result)
                elif "%" in op_name:
                    result, may_div_zero = left.mod(right)
                    if (
                        may_div_zero
                        and not right.must_be_non_zero()
                        and right.is_numeric
                        and left.is_numeric
                    ):
                        warnings.append(
                            RangeWarning(
                                line=line,
                                pc=instr.offset,
                                kind="MODULO_BY_ZERO",
                                message=f"Possible modulo by zero (divisor range: {right})",
                                range_info=right,
                            )
                        )
                    state.push(result)
                else:
                    state.push(Range.full())
        elif opname == "UNARY_NEGATIVE":
            if state.stack:
                state.push(state.pop().neg())
        elif opname == "UNARY_POSITIVE":
            pass
        elif opname == "COMPARE_OP":
            if len(state.stack) >= 2:
                state.pop()
                state.pop()
            state.push(Range.between(0, 1))
        elif opname == "BINARY_SUBSCR":
            if len(state.stack) >= 2:
                index = state.pop()
                container = state.pop() if state.stack else None

                container_name = str(container) if container else ""
                is_type_sub = False
                if hasattr(container, "_name"):
                    container_name = str(getattr(container, "name", ""))
                if container_name.startswith(("global_", "import_")):
                    from pysymex.core.type_checks import BUILTIN_TYPE_NAMES

                    base = container_name.split("_", 1)[1] if "_" in container_name else ""
                    is_type_sub = base in BUILTIN_TYPE_NAMES
                if not is_type_sub and index.must_be_negative():
                    pass
                state.push(Range.full())
            else:
                pass
        elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET"}:
            count = arg or 0
            for _ in range(count):
                if state.stack:
                    state.pop()
            state.push(Range.exact(count))
        elif opname == "BUILD_MAP":
            count = arg or 0
            for _ in range(count * 2):
                if state.stack:
                    state.pop()
            state.push(Range.exact(count))
        elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            arg_count = arg if arg is not None else 0
            for _ in range(arg_count):
                if state.stack:
                    state.pop()
            if state.stack:
                state.pop()
            state.push(Range.full())
        elif opname == "POP_TOP":
            if state.stack:
                state.pop()
        elif opname == "DUP_TOP":
            if state.stack:
                state.push(state.peek())
        elif opname == "ROT_TWO":
            if len(state.stack) >= 2:
                a = state.pop()
                b = state.pop()
                state.push(a)
                state.push(b)
        elif opname == "RETURN_VALUE":
            if state.stack:
                state.pop()
        elif opname == "LOAD_ATTR":
            if state.stack:
                state.pop()
            if arg == "__len__":
                state.push(Range.at_least(0))
            else:
                state.push(Range.full())
        elif opname == "STORE_ATTR":
            if len(state.stack) >= 2:
                state.pop()
                state.pop()
        return warnings


class ValueRangeChecker:
    """
    High-level interface for value range checking.
    """

    def __init__(self) -> None:
        self.analyzer = RangeAnalyzer()

    def check_function(
        self,
        code: types.CodeType,
        file_path: str = "<unknown>",
    ) -> list[RangeWarning]:
        """Check a function for range-related issues."""
        _, warnings = self.analyzer.analyze(code, file_path)
        return warnings

    def check_array_bounds(
        self,
        index_range: Range,
        array_size: int,
    ) -> str | None:
        """Check if index range is within array bounds."""
        if index_range.is_empty:
            return None
        if index_range.low is not None and index_range.low < -array_size:
            return f"Index may be too negative: {index_range}"
        if index_range.high is not None and index_range.high >= array_size:
            return f"Index may be out of bounds: {index_range} (size: {array_size})"
        return None
