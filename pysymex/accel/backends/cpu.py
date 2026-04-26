# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Numba Parallel CPU Backend.

Uses Numba's parallel JIT compilation to evaluate constraints on
multi-core CPUs. Achieves near-linear speedup with core count for
embarrassingly parallel workloads.

Performance: O(2^w * instructions / num_cores)
Memory: O(2^w / 8) bytes output
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

import numpy as np
import numpy.typing as npt

from pysymex.accel.backends import BackendError, BackendInfo, BackendType

if TYPE_CHECKING:
    from pysymex.accel.bytecode import CompiledConstraint

__all__ = ["evaluate_bag", "get_info", "is_available", "warmup"]

MAX_TREEWIDTH: int = 28


def is_available() -> bool:
    """Check if Numba is available."""
    try:
        import numba

        _ = numba
        return True
    except ImportError:
        return False


def get_info() -> BackendInfo:
    """Get backend information."""
    if not is_available():
        return BackendInfo(
            backend_type=BackendType.CPU,
            name="Numba CPU (parallel)",
            available=False,
            max_treewidth=0,
            error_message="Numba not installed",
        )

    cores = os.cpu_count() or 1
    return BackendInfo(
        backend_type=BackendType.CPU,
        name=f"Numba CPU ({cores} cores)",
        available=True,
        max_treewidth=MAX_TREEWIDTH,
        supports_async=False,
        compute_units=cores,
    )


try:
    from numba import njit, prange

    @njit(
        parallel=True,
        fastmath=True,
        cache=True,
        boundscheck=False,
        nogil=True,
    )
    def _evaluate_parallel(
        num_vars: int,
        num_instructions: int,
        opcodes: npt.NDArray[np.uint16],
        dsts: npt.NDArray[np.uint16],
        src1s: npt.NDArray[np.uint16],
        src2s: npt.NDArray[np.uint16],
        imms: npt.NDArray[np.uint16],
        output: npt.NDArray[np.uint8],
        register_count: int,
    ) -> None:
        """Parallel bit-sliced CPU evaluation kernel.

        Processes 64 assignments per iteration using bitwise operations.
        """
        num_states = 1 << num_vars
        num_chunks = (num_states + 63) // 64

        for chunk_idx in prange(num_chunks):
            base_tid = int(chunk_idx) * 64
            registers = np.zeros(register_count, dtype=np.uint64)

            for i in range(num_vars):
                if i == 0:
                    registers[i + 1] = 0xAAAAAAAAAAAAAAAA
                elif i == 1:
                    registers[i + 1] = 0xCCCCCCCCCCCCCCCC
                elif i == 2:
                    registers[i + 1] = 0xF0F0F0F0F0F0F0F0
                elif i == 3:
                    registers[i + 1] = 0xFF00FF00FF00FF00
                elif i == 4:
                    registers[i + 1] = 0xFFFF0000FFFF0000
                elif i == 5:
                    registers[i + 1] = 0xFFFFFFFF00000000
                else:
                    if (base_tid >> i) & 1:
                        registers[i + 1] = 0xFFFFFFFFFFFFFFFF
                    else:
                        registers[i + 1] = 0

            for pc in range(num_instructions):
                op = opcodes[pc]
                dst = dsts[pc]
                s1 = src1s[pc]
                s2 = src2s[pc]
                imm = imms[pc]
                if op == 0xFF:
                    break
                elif op == 0x01:
                    registers[dst] = registers[imm + 1]
                elif op == 0x02:
                    registers[dst] = 0xFFFFFFFFFFFFFFFF
                elif op == 0x03:
                    registers[dst] = 0
                elif op == 0x04:
                    registers[dst] = registers[s1]
                elif op == 0x10:
                    registers[dst] = registers[s1] & registers[s2]
                elif op == 0x11:
                    registers[dst] = registers[s1] | registers[s2]
                elif op == 0x12:
                    registers[dst] = ~registers[s1]
                elif op == 0x13:
                    registers[dst] = registers[s1] ^ registers[s2]
                elif op == 0x16:
                    registers[dst] = (~registers[s1]) | registers[s2]
                elif op == 0x17:
                    registers[dst] = ~(registers[s1] ^ registers[s2])
                elif op == 0x30:
                    registers[dst] = (registers[s1] & registers[s2]) | (
                        (~registers[s1]) & registers[imm]
                    )

            res = registers[0]
            if res != 0:
                if base_tid + 64 > num_states:
                    remaining = num_states - base_tid
                    mask = (1 << remaining) - 1
                    res = np.uint64(int(res) & mask)

                if res != 0:
                    byte_start = base_tid >> 3
                    for b in range(8):
                        out_idx = byte_start + b
                        if out_idx < int(output.size):
                            output[out_idx] = np.uint8((int(res) >> (b * 8)) & 0xFF)

except ImportError:

    def _evaluate_parallel(
        num_vars: int,
        num_instructions: int,
        opcodes: npt.NDArray[np.uint16],
        dsts: npt.NDArray[np.uint16],
        src1s: npt.NDArray[np.uint16],
        src2s: npt.NDArray[np.uint16],
        imms: npt.NDArray[np.uint16],
        output: npt.NDArray[np.uint8],
        register_count: int,
    ) -> None:
        raise BackendError("Numba not installed")


def evaluate_bag(constraint: CompiledConstraint) -> npt.NDArray[np.uint8]:
    """Evaluate constraint using parallel CPU threads.

    Args:
        constraint: Compiled constraint

    Returns:
        Packed bitmap of satisfying assignments

    Raises:
        ValueError: If treewidth exceeds maximum
        BackendError: If evaluation fails
    """
    if not is_available():
        raise BackendError("Numba CPU backend not available")

    w = constraint.num_variables
    num_states = 1 << w

    if w > MAX_TREEWIDTH:
        raise ValueError(f"Treewidth {w} exceeds CPU backend maximum ({MAX_TREEWIDTH})")

    instr = constraint.instructions
    instr_fields = cast("Mapping[str, object]", instr)
    opcode_field = cast("npt.NDArray[np.uint16]", instr_fields["opcode"])
    dst_field = cast("npt.NDArray[np.uint16]", instr_fields["dst"])
    src1_field = cast("npt.NDArray[np.uint16]", instr_fields["src1"])
    src2_field = cast("npt.NDArray[np.uint16]", instr_fields["src2"])
    imm_field = cast("npt.NDArray[np.uint16]", instr_fields["immediate"])
    opcodes = cast("npt.NDArray[np.uint16]", np.ascontiguousarray(opcode_field, dtype=np.uint16))
    dsts = cast("npt.NDArray[np.uint16]", np.ascontiguousarray(dst_field, dtype=np.uint16))
    src1s = cast("npt.NDArray[np.uint16]", np.ascontiguousarray(src1_field, dtype=np.uint16))
    src2s = cast("npt.NDArray[np.uint16]", np.ascontiguousarray(src2_field, dtype=np.uint16))
    imms = cast("npt.NDArray[np.uint16]", np.ascontiguousarray(imm_field, dtype=np.uint16))

    bitmap_size = (num_states + 7) // 8
    output: npt.NDArray[np.uint8] = np.zeros(bitmap_size, dtype=np.uint8)

    _evaluate_parallel(
        w,
        int(opcodes.size),
        opcodes,
        dsts,
        src1s,
        src2s,
        imms,
        output,
        constraint.register_count,
    )

    return output


def warmup() -> None:
    """Warm up JIT compilation.

    Call this once at startup to avoid compilation latency
    on first use.
    """
    if not is_available():
        return

    from pysymex.accel.bytecode import compile_constraint

    try:
        import z3

        a, b = z3.Bools("a b")
        constraint = compile_constraint(z3.And(a, b), ["a", "b"])
        evaluate_bag(constraint)
    except ImportError:
        pass
