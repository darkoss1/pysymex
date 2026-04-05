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

"""GPU Bytecode Instruction Set Architecture and Z3-to-Bytecode Compiler.

This module defines a minimal, GPU-optimized instruction set for evaluating
Boolean constraints. The ISA is designed for:
- Minimal warp divergence (no branching opcodes)
- Coalesced memory access (fixed 128-bit instruction encoding)
- Register-based execution (up to 8192 virtual registers)
- Bit-exact semantics (integer-only operations)
"""

from __future__ import annotations

import threading
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Final

import numpy as np
import numpy.typing as npt

from pysymex.core.constraint_hash import structural_hash

if TYPE_CHECKING:
    import z3

__all__ = [
    "INSTRUCTION_DTYPE",
    "MAX_INSTRUCTIONS",
    "MAX_REGISTERS",
    "MAX_VARIABLES",
    "BytecodeCompiler",
    "CompiledConstraint",
    "Instruction",
    "Opcode",
    "compile_constraint",
    "disassemble",
]

MAX_REGISTERS: Final[int] = 8192
MAX_VARIABLES: Final[int] = 40
MAX_INSTRUCTIONS: Final[int] = 8192

_compile_cache: dict[tuple[int, tuple[str, ...]], CompiledConstraint] = {}
_compile_lock = threading.Lock()


class Opcode(IntEnum):
    """GPU bytecode opcodes.

    Grouped by function:
    - 0x00-0x0F: Control & Load
    - 0x10-0x1F: Binary Boolean Operations
    - 0x20-0x2F: Comparison Operations
    - 0xF0-0xFF: Reserved/Control Flow
    """

    NOP = 0x00
    LOAD_VAR = 0x01
    LOAD_TRUE = 0x02
    LOAD_FALSE = 0x03
    COPY = 0x04
    AND = 0x10
    OR = 0x11
    NOT = 0x12
    XOR = 0x13
    NAND = 0x14
    NOR = 0x15
    IMPLIES = 0x16
    IFF = 0x17
    EQ = 0x20
    NE = 0x21
    EQ_CONST = 0x22
    ITE = 0x30
    HALT = 0xFF


INSTRUCTION_DTYPE: Final[np.dtype[np.void]] = np.dtype(
    [
        ("opcode", np.uint16),
        ("dst", np.uint16),
        ("src1", np.uint16),
        ("src2", np.uint16),
        ("flags", np.uint16),
        ("immediate", np.uint16),
        ("padding1", np.uint16),
        ("padding2", np.uint16),
    ],
    align=True,
)

assert INSTRUCTION_DTYPE.itemsize == 16, (
    f"Instruction size must be 16 bytes, got {INSTRUCTION_DTYPE.itemsize}"
)


@dataclass(frozen=True, slots=True)
class Instruction:
    """Single bytecode instruction.

    Immutable value type representing one GPU operation.

    Attributes:
        opcode: Operation to perform
        dst: Destination register (0 to MAX_REGISTERS-1)
        src1: First source register (0 to MAX_REGISTERS-1)
        src2: Second source register (0 to MAX_REGISTERS-1)
        flags: Reserved for future extensions
        immediate: Immediate value (variable index, constant, etc.)
    """

    opcode: Opcode
    dst: int = 0
    src1: int = 0
    src2: int = 0
    flags: int = 0
    immediate: int = 0

    def __post_init__(self) -> None:
        """Validate instruction fields."""
        if not (0 <= self.dst < MAX_REGISTERS):
            raise ValueError(f"dst must be 0-{MAX_REGISTERS - 1}, got {self.dst}")
        if not (0 <= self.src1 < MAX_REGISTERS):
            raise ValueError(f"src1 must be 0-{MAX_REGISTERS - 1}, got {self.src1}")
        if not (0 <= self.src2 < MAX_REGISTERS):
            raise ValueError(f"src2 must be 0-{MAX_REGISTERS - 1}, got {self.src2}")
        if not (0 <= self.immediate < 65536):
            raise ValueError(f"immediate must be 0-65535, got {self.immediate}")

    def to_tuple(self) -> tuple[int, int, int, int, int, int, int, int]:
        """Convert to tuple for NumPy assignment."""
        return (int(self.opcode), self.dst, self.src1, self.src2, self.flags, self.immediate, 0, 0)

    def __repr__(self) -> str:
        op_name = self.opcode.name
        if self.opcode in (Opcode.NOP, Opcode.HALT):
            return op_name
        elif self.opcode == Opcode.LOAD_VAR:
            return f"{op_name} R{self.dst}, var[{self.immediate}]"
        elif self.opcode in (Opcode.LOAD_TRUE, Opcode.LOAD_FALSE):
            return f"{op_name} R{self.dst}"
        elif self.opcode == Opcode.NOT:
            return f"{op_name} R{self.dst}, R{self.src1}"
        elif self.opcode == Opcode.EQ_CONST:
            return f"{op_name} R{self.dst}, R{self.src1}, {self.immediate}"
        else:
            return f"{op_name} R{self.dst}, R{self.src1}, R{self.src2}"


@dataclass(frozen=True, slots=True)
class CompiledConstraint:
    """Compiled constraint ready for GPU execution.

    Contains the bytecode instruction stream and metadata needed
    for kernel launch configuration and memory allocation.

    Attributes:
        instructions: NumPy array of instructions (GPU-transferable)
        num_variables: Number of Boolean variables (= bag treewidth)
        register_count: Number of registers used (for occupancy analysis)
        source_hash: Hash of source Z3 expression (for caching)
    """

    instructions: npt.NDArray[np.void]
    num_variables: int
    register_count: int
    source_hash: int = 0

    def __post_init__(self) -> None:
        """Validate compiled constraint."""
        if self.instructions.dtype != INSTRUCTION_DTYPE:
            raise TypeError(f"instructions must have dtype {INSTRUCTION_DTYPE}")
        if not (0 < self.num_variables <= MAX_VARIABLES):
            raise ValueError(f"num_variables must be 1-{MAX_VARIABLES}, got {self.num_variables}")
        if not (0 < self.register_count <= MAX_REGISTERS):
            raise ValueError(f"register_count must be 1-{MAX_REGISTERS}, got {self.register_count}")

    @property
    def instruction_count(self) -> int:
        """Number of instructions in the stream."""
        return len(self.instructions)

    @property
    def num_states(self) -> int:
        """Number of possible Boolean assignments (2^num_variables)."""
        return 1 << self.num_variables

    @property
    def output_bitmap_size(self) -> int:
        """Size of output bitmap in bytes."""
        return (self.num_states + 7) // 8

    def memory_bytes(self) -> int:
        """Total device memory required (instructions + output)."""
        return int(self.instructions.nbytes) + self.output_bitmap_size

    def __repr__(self) -> str:
        return (
            f"CompiledConstraint(vars={self.num_variables}, "
            f"instrs={self.instruction_count}, regs={self.register_count})"
        )


class BytecodeCompiler:
    """Compiles Z3 Boolean expressions to GPU bytecode.

    The compiler performs a single-pass recursive descent over the Z3 AST,
    emitting instructions in postorder (operands before operation).

    Register Allocation:
        R[0]: Reserved for final result
        R[1..w]: Pre-loaded with variable values (by GPU kernel)
        R[w+1..MAX_REGISTERS-1]: Temporaries for intermediate results

    Thread Safety:
        NOT thread-safe. Create new instance per compilation or use
        compile_constraint() function which creates fresh instances.
    """

    def __init__(self) -> None:
        self._reset()

    def _reset(self) -> None:
        """Reset compiler state for new compilation."""
        self._register_counter: int = 1
        self._var_to_index: dict[str, int] = {}
        self._instructions: list[Instruction] = []
        self._expr_cache: dict[int, int] = {}

    def compile(
        self,
        expr: z3.ExprRef,
        variables: Sequence[str],
    ) -> CompiledConstraint:
        """Compile a Z3 Boolean expression to GPU bytecode.

        Args:
            expr: Z3 Boolean expression (conjunction of constraints)
            variables: Ordered list of variable names (defines bit positions)

        Returns:
            CompiledConstraint ready for GPU execution
        """

        self._reset()

        if len(variables) > MAX_VARIABLES:
            raise ValueError(f"Too many variables: {len(variables)} > {MAX_VARIABLES}")
        if len(variables) == 0:
            raise ValueError("At least one variable required")

        ordered_vars = self._order_variables_by_frequency(expr, list(variables))

        for i, var_name in enumerate(ordered_vars):
            self._var_to_index[var_name] = i

        self._register_counter = len(ordered_vars) + 1

        self._cse_cache: dict[str, int] = {}

        result_reg = self._compile_expr(expr)

        if result_reg != 0:
            self._emit(Opcode.COPY, dst=0, src1=result_reg)

        self._emit(Opcode.HALT)

        if len(self._instructions) > MAX_INSTRUCTIONS:
            raise ValueError(
                f"Too many instructions: {len(self._instructions)} > {MAX_INSTRUCTIONS}"
            )

        instr_array = np.zeros(len(self._instructions), dtype=INSTRUCTION_DTYPE)
        for i, instr in enumerate(self._instructions):
            instr_array[i] = instr.to_tuple()

        source_hash = structural_hash([expr]) & 0xFFFFFFFF

        return CompiledConstraint(
            instructions=instr_array,
            num_variables=len(ordered_vars),
            register_count=self._register_counter,
            source_hash=source_hash,
        )

    def _alloc_register(self) -> int:
        """Allocate a fresh register."""
        reg = self._register_counter
        self._register_counter += 1
        if reg >= MAX_REGISTERS - 1:
            raise ValueError(
                f"Register overflow: expression too complex. "
                f"Used {reg} registers, max is {MAX_REGISTERS - 2}"
            )
        return reg

    def _emit(
        self,
        opcode: Opcode,
        dst: int = 0,
        src1: int = 0,
        src2: int = 0,
        flags: int = 0,
        immediate: int = 0,
    ) -> None:
        """Emit an instruction to the stream."""
        self._instructions.append(Instruction(opcode, dst, src1, src2, flags, immediate))

    def _order_variables_by_frequency(self, expr: z3.ExprRef, variables: list[str]) -> list[str]:
        """Reorder variables so the most referenced ones are at indices 0-5."""
        import z3

        freq: dict[str, int] = dict.fromkeys(variables, 0)
        seen: set[int] = set()

        def count(e: z3.ExprRef) -> None:
            e_id = e.get_id()
            if e_id in seen:
                return
            seen.add(e_id)

            if z3.is_const(e) and e.sort() == z3.BoolSort():
                try:
                    name = e.decl().name()
                except Exception:
                    name = None
                if isinstance(name, str) and name in freq:
                    freq[name] += 1
            for i in range(e.num_args()):
                count(e.arg(i))

        try:
            count(expr)
        except Exception:
            return variables

        return sorted(variables, key=lambda v: -freq.get(v, 0))

    def _canonical_key(self, expr: z3.ExprRef) -> str:
        """Structural hash key for Common Subexpression Elimination."""
        import z3

        if not hasattr(self, "_canonical_cache"):
            self._canonical_cache: dict[int, str] = {}

        e_id = expr.get_id()
        if e_id in self._canonical_cache:
            return self._canonical_cache[e_id]

        if z3.is_const(expr):
            res = f"v:{expr.hash()}"
            self._canonical_cache[e_id] = res
            return res
        if z3.is_true(expr):
            self._canonical_cache[e_id] = "T"
            return "T"
        if z3.is_false(expr):
            self._canonical_cache[e_id] = "F"
            return "F"

        decl = expr.decl()
        kind = decl.kind()

        child_keys = [self._canonical_key(expr.arg(i)) for i in range(expr.num_args())]
        if kind in (z3.Z3_OP_AND, z3.Z3_OP_OR, z3.Z3_OP_XOR, z3.Z3_OP_IFF, z3.Z3_OP_DISTINCT):
            child_keys.sort()

        res = f"{kind}({','.join(child_keys)})"
        self._canonical_cache[e_id] = res
        return res

    def _compile_expr(self, expr: z3.ExprRef) -> int:
        """Recursively compile Z3 expression to bytecode.

        Uses both Z3 ID cache and structural CSE cache.
        """
        expr_id = expr.get_id()
        if expr_id in self._expr_cache:
            return self._expr_cache[expr_id]

        ck = self._canonical_key(expr)
        if hasattr(self, "_cse_cache") and ck in self._cse_cache:
            res = self._cse_cache[ck]
            self._expr_cache[expr_id] = res
            return res

        result_reg = self._compile_expr_uncached(expr)

        self._expr_cache[expr_id] = result_reg
        if hasattr(self, "_cse_cache"):
            self._cse_cache[ck] = result_reg

        return result_reg

    def _compile_expr_uncached(self, expr: z3.ExprRef) -> int:
        """Compile expression without cache lookup."""
        import z3

        if z3.is_true(expr):
            reg = self._alloc_register()
            self._emit(Opcode.LOAD_TRUE, dst=reg)
            return reg

        if z3.is_false(expr):
            reg = self._alloc_register()
            self._emit(Opcode.LOAD_FALSE, dst=reg)
            return reg

        if z3.is_const(expr) and expr.sort() == z3.BoolSort():
            var_name = expr.decl().name()
            if var_name not in self._var_to_index:
                raise ValueError(
                    f"Unknown variable '{var_name}'. "
                    f"Known variables: {list(self._var_to_index.keys())}"
                )
            var_idx = self._var_to_index[var_name]
            return var_idx + 1

        decl = expr.decl()
        kind = decl.kind()
        children: list[z3.ExprRef] = [expr.arg(i) for i in range(expr.num_args())]

        if kind == z3.Z3_OP_AND:
            return self._compile_nary(Opcode.AND, children, identity_value=True)

        elif kind == z3.Z3_OP_OR:
            return self._compile_nary(Opcode.OR, children, identity_value=False)

        elif kind == z3.Z3_OP_NOT:
            child_reg = self._compile_expr(children[0])
            result_reg = self._alloc_register()
            self._emit(Opcode.NOT, dst=result_reg, src1=child_reg)
            return result_reg

        elif kind == z3.Z3_OP_XOR:
            return self._compile_nary(Opcode.XOR, children, identity_value=False)

        elif kind == z3.Z3_OP_IMPLIES:
            left_reg = self._compile_expr(children[0])
            right_reg = self._compile_expr(children[1])
            result_reg = self._alloc_register()
            self._emit(Opcode.IMPLIES, dst=result_reg, src1=left_reg, src2=right_reg)
            return result_reg

        elif kind in (z3.Z3_OP_IFF, z3.Z3_OP_EQ):
            if len(children) == 2 and children[0].sort() == z3.BoolSort():
                left_reg = self._compile_expr(children[0])
                right_reg = self._compile_expr(children[1])
                result_reg = self._alloc_register()
                self._emit(Opcode.IFF, dst=result_reg, src1=left_reg, src2=right_reg)
                return result_reg

        elif kind == z3.Z3_OP_DISTINCT:
            if len(children) == 2 and children[0].sort() == z3.BoolSort():
                left_reg = self._compile_expr(children[0])
                right_reg = self._compile_expr(children[1])
                result_reg = self._alloc_register()
                self._emit(Opcode.XOR, dst=result_reg, src1=left_reg, src2=right_reg)
                return result_reg

        elif kind == z3.Z3_OP_ITE:
            cond_reg = self._compile_expr(children[0])
            then_reg = self._compile_expr(children[1])
            else_reg = self._compile_expr(children[2])
            result_reg = self._alloc_register()
            self._emit(Opcode.ITE, dst=result_reg, src1=cond_reg, src2=then_reg, immediate=else_reg)
            return result_reg

        warnings.warn(
            f"Unsupported Z3 expression kind {kind}: {expr}. "
            "Treating as TRUE (conservative approximation).",
            RuntimeWarning,
            stacklevel=2,
        )
        reg = self._alloc_register()
        self._emit(Opcode.LOAD_TRUE, dst=reg)
        return reg

    def _compile_nary(
        self,
        opcode: Opcode,
        children: list[z3.ExprRef],
        identity_value: bool,
    ) -> int:
        """Compile n-ary Boolean operations (AND, OR, XOR).

        Uses left-to-right associative folding with constant simplification.

        Args:
            opcode: Binary operation to apply
            children: Child expressions
            identity_value: Value for empty case (True for AND, False for OR)

        Returns:
            Register containing result
        """
        import z3

        filtered_children = []
        for child in children:
            if z3.is_true(child):
                if opcode == Opcode.OR:
                    reg = self._alloc_register()
                    self._emit(Opcode.LOAD_TRUE, dst=reg)
                    return reg
                if opcode == Opcode.XOR:
                    filtered_children.append(child)
                    continue

                continue
            if z3.is_false(child):
                if opcode == Opcode.AND:
                    reg = self._alloc_register()
                    self._emit(Opcode.LOAD_FALSE, dst=reg)
                    return reg

                continue
            filtered_children.append(child)

        if not filtered_children:
            reg = self._alloc_register()
            if identity_value:
                self._emit(Opcode.LOAD_TRUE, dst=reg)
            else:
                self._emit(Opcode.LOAD_FALSE, dst=reg)
            return reg

        if len(filtered_children) == 1:
            return self._compile_expr(filtered_children[0])

        result_reg = self._compile_expr(filtered_children[0])

        fold_reg: int | None = None
        for child in filtered_children[1:]:
            child_reg = self._compile_expr(child)

            if fold_reg is None:
                fold_reg = self._alloc_register()

            self._emit(opcode, dst=fold_reg, src1=result_reg, src2=child_reg)
            result_reg = fold_reg

        return result_reg


def compile_constraint(
    expr: z3.ExprRef,
    variables: Sequence[str],
) -> CompiledConstraint:
    """Compile Z3 Boolean expression to GPU bytecode.

    This is the primary public API for compilation. Uses an in-memory cache
    to avoid redundant compilations of the same expression.

    Args:
        expr: Z3 Boolean expression (typically a conjunction of constraints)
        variables: Ordered list of variable names

    Returns:
        CompiledConstraint ready for GPU execution
    """

    key = (structural_hash([expr]), tuple(variables))

    with _compile_lock:
        if key in _compile_cache:
            return _compile_cache[key]

    compiler = BytecodeCompiler()
    result = compiler.compile(expr, variables)

    with _compile_lock:
        _compile_cache[key] = result

    return result


def disassemble(constraint: CompiledConstraint) -> str:
    """Disassemble compiled constraint to human-readable format.

    Useful for debugging and understanding generated code.

    Args:
        constraint: Compiled constraint to disassemble

    Returns:
        Multi-line string with instruction listing
    """
    lines: list[str] = [
        f"; CompiledConstraint: {constraint.num_variables} vars, "
        f"{constraint.instruction_count} instructions",
        f"; Registers used: {constraint.register_count}",
        f"; Output bitmap: {constraint.output_bitmap_size} bytes",
        "",
    ]

    for i, instr_data in enumerate(constraint.instructions):
        op = Opcode(int(instr_data["opcode"]))
        dst = int(instr_data["dst"])
        src1 = int(instr_data["src1"])
        src2 = int(instr_data["src2"])
        imm = int(instr_data["immediate"])

        if op in (Opcode.NOP, Opcode.HALT):
            asm = op.name
        elif op == Opcode.LOAD_VAR:
            asm = f"LOAD_VAR  R{dst}, var[{imm}]"
        elif op == Opcode.LOAD_TRUE:
            asm = f"LOAD_TRUE R{dst}"
        elif op == Opcode.LOAD_FALSE:
            asm = f"LOAD_FALSE R{dst}"
        elif op == Opcode.COPY:
            asm = f"COPY      R{dst}, R{src1}"
        elif op == Opcode.NOT:
            asm = f"NOT       R{dst}, R{src1}"
        elif op == Opcode.EQ_CONST:
            asm = f"EQ_CONST  R{dst}, R{src1}, {imm}"
        elif op == Opcode.ITE:
            asm = f"ITE       R{dst}, R{src1}, R{src2}, R{imm}"
        else:
            asm = f"{op.name:10s} R{dst}, R{src1}, R{src2}"

        lines.append(f"  {i:4d}:  {asm}")

    return "\n".join(lines)
