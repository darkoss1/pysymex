"""Numba Parallel CPU Backend.

Uses Numba's parallel JIT compilation to evaluate constraints on
multi-core CPUs. Achieves near-linear speedup with core count for
embarrassingly parallel workloads.

Performance: O(2^w * instructions / num_cores)
Memory: O(2^w / 8) bytes output
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import numpy as np
import numpy.typing as npt

from pysymex.h_acceleration.backends import BackendError, BackendInfo, BackendType

if TYPE_CHECKING:
    from pysymex.h_acceleration.bytecode import CompiledConstraint

__all__ = ["evaluate_bag", "get_info", "is_available", "warmup"]

MAX_TREEWIDTH: int = 28

def is_available() -> bool:
    """Check if Numba is available."""
    try:
        from numba import njit, prange
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
    from numba import njit, prange, uint8, uint16, uint32, uint64

    @njit(  # pyright: ignore[reportUntypedFunctionDecorator]
        parallel=True,
        fastmath=True,
        cache=True,
        boundscheck=False,
        nogil=True,
    )
    def _evaluate_parallel(
        num_vars: np.uint8,
        num_instructions: np.uint32,
        opcodes: npt.NDArray[np.uint16],
        dsts: npt.NDArray[np.uint16],
        src1s: npt.NDArray[np.uint16],
        src2s: npt.NDArray[np.uint16],
        imms: npt.NDArray[np.uint16],
        output: npt.NDArray[np.uint8],
    ) -> None:
        """Parallel bit-sliced CPU evaluation kernel.

        Processes 64 assignments per iteration using bitwise operations.
        """
        num_states = uint64(1) << num_vars
        num_chunks = (num_states + uint64(63)) // uint64(64)

        for chunk_idx in prange(num_chunks):
            base_tid = uint64(chunk_idx) * 64
            registers = np.zeros(8192, dtype=uint64) # pyright: ignore[reportCallIssue, reportArgumentType]

            for i in range(num_vars):
                if i == 0:
                    registers[i + 1] = uint64(0xAAAAAAAAAAAAAAAA)
                elif i == 1:
                    registers[i + 1] = uint64(0xCCCCCCCCCCCCCCCC)
                elif i == 2:
                    registers[i + 1] = uint64(0xF0F0F0F0F0F0F0F0)
                elif i == 3:
                    registers[i + 1] = uint64(0xFF00FF00FF00FF00)
                elif i == 4:
                    registers[i + 1] = uint64(0xFFFF0000FFFF0000)
                elif i == 5:
                    registers[i + 1] = uint64(0xFFFFFFFF00000000)
                else:

                    if (base_tid >> i) & 1:
                        registers[i + 1] = uint64(0xFFFFFFFFFFFFFFFF)
                    else:
                        registers[i + 1] = uint64(0)

            for pc in range(num_instructions):
                op = opcodes[pc]; dst = dsts[pc]; s1 = src1s[pc]; s2 = src2s[pc]; imm = imms[pc]
                if op == 0xFF: break
                elif op == 0x01: registers[dst] = registers[imm + 1]
                elif op == 0x02: registers[dst] = uint64(0xFFFFFFFFFFFFFFFF)
                elif op == 0x03: registers[dst] = 0
                elif op == 0x04: registers[dst] = registers[s1]
                elif op == 0x10: registers[dst] = registers[s1] & registers[s2]
                elif op == 0x11: registers[dst] = registers[s1] | registers[s2]
                elif op == 0x12: registers[dst] = ~registers[s1]
                elif op == 0x13: registers[dst] = registers[s1] ^ registers[s2]
                elif op == 0x16: registers[dst] = (~registers[s1]) | registers[s2]
                elif op == 0x17: registers[dst] = ~(registers[s1] ^ registers[s2])
                elif op == 0x30: registers[dst] = (registers[s1] & registers[s2]) | ((~registers[s1]) & registers[imm])

            res = registers[0]
            if res != 0:

                if base_tid + uint64(64) > num_states:
                    remaining = num_states - base_tid
                    mask = (uint64(1) << remaining) - uint64(1)
                    res &= mask

                if res != 0:
                    byte_start = base_tid >> 3
                    for b in range(8):
                        if byte_start + uint64(b) < uint64(len(output)): # pyright: ignore[reportOperatorIssue]
                            output[byte_start + b] = uint8((res >> (b * 8)) & 0xFF) # pyright: ignore[reportCallIssue, reportArgumentType]

except ImportError:
    def _evaluate_parallel(
        num_vars: np.uint8,
        num_instructions: np.uint32,
        opcodes: npt.NDArray[np.uint16],
        dsts: npt.NDArray[np.uint16],
        src1s: npt.NDArray[np.uint16],
        src2s: npt.NDArray[np.uint16],
        imms: npt.NDArray[np.uint16],
        output: npt.NDArray[np.uint8],
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
        raise ValueError(
            f"Treewidth {w} exceeds CPU backend maximum ({MAX_TREEWIDTH})"
        )

    instr = constraint.instructions
    opcodes = np.ascontiguousarray(instr['opcode'])
    dsts = np.ascontiguousarray(instr['dst'])
    src1s = np.ascontiguousarray(instr['src1'])
    src2s = np.ascontiguousarray(instr['src2'])
    imms = np.ascontiguousarray(instr['immediate'])

    bitmap_size = (num_states + 7) // 8
    output: npt.NDArray[np.uint8] = np.zeros(bitmap_size, dtype=np.uint8)

    _evaluate_parallel(
        np.uint8(w),
        np.uint32(len(instr)),
        opcodes, dsts, src1s, src2s, imms,
        output,
    )

    return output

def warmup() -> None:
    """Warm up JIT compilation.

    Call this once at startup to avoid compilation latency
    on first use.
    """
    if not is_available():
        return

    from pysymex.h_acceleration.bytecode import compile_constraint
    try:
        import z3
        a, b = z3.Bools('a b')
        constraint = compile_constraint(z3.And(a, b), ['a', 'b'])
        evaluate_bag(constraint)
    except ImportError:
        pass
