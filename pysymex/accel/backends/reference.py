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

"""Pure Python Reference Backend.

This backend provides a bit-exact reference implementation for testing.
It is intentionally simple and unoptimized to serve as ground truth
for validating other backends.

Performance: O(2^w * instructions) â€” usable only for w â‰¤ 14
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import numpy as np
import numpy.typing as npt

from pysymex.accel.backends import BackendInfo, BackendType

if TYPE_CHECKING:
    from pysymex.accel.bytecode import CompiledConstraint

__all__ = [
    "count_sat",
    "count_satisfying",
    "evaluate_bag",
    "get_info",
    "get_satisfying_assignments",
    "is_available",
    "warmup",
]

MAX_TREEWIDTH: int = 14


def is_available() -> bool:
    """Reference backend is always available (pure Python)."""
    return True


def get_info() -> BackendInfo:
    """Get backend information."""
    return BackendInfo(
        backend_type=BackendType.REFERENCE,
        name="Pure Python (reference)",
        available=True,
        max_treewidth=MAX_TREEWIDTH,
        supports_async=False,
        device_memory_mb=0,
        compute_units=1,
    )


def evaluate_bag(constraint: CompiledConstraint) -> npt.NDArray[np.uint8]:
    """Evaluate constraint using pure Python.

    This implementation prioritizes correctness and clarity over performance.
    It serves as the reference for validating SAT backends.

    Algorithm:
        For each possible assignment (0 to 2^w - 1):
            1. Extract Boolean values from assignment bits
            2. Execute instruction stream
            3. Record result in output bitmap

    Args:
        constraint: Compiled constraint

    Returns:
        Packed bitmap of satisfying assignments

    Raises:
        ValueError: If treewidth exceeds maximum
    """

    w = constraint.num_variables
    num_states = 1 << w

    if w > MAX_TREEWIDTH:
        raise ValueError(
            f"Treewidth {w} exceeds reference backend maximum ({MAX_TREEWIDTH}). "
            "Use SAT or CPU backend for larger problems."
        )

    bitmap_size = (num_states + 7) // 8
    output: npt.NDArray[np.uint8] = np.zeros(bitmap_size, dtype=np.uint8)

    instr = constraint.instructions
    opcodes = cast("npt.NDArray[np.uint8]", instr["opcode"])
    dsts = cast("npt.NDArray[np.uint8]", instr["dst"])
    src1s = cast("npt.NDArray[np.uint8]", instr["src1"])
    src2s = cast("npt.NDArray[np.uint8]", instr["src2"])
    imms = cast("npt.NDArray[np.uint8]", instr["immediate"])
    num_instructions = len(instr)
    num_regs = constraint.register_count

    for tid in range(num_states):
        registers: list[int] = [0] * num_regs

        for i in range(w):
            registers[i + 1] = (tid >> i) & 1

        for pc in range(num_instructions):
            op = int(opcodes[pc])
            dst = int(dsts[pc])
            s1 = int(src1s[pc])
            s2 = int(src2s[pc])
            imm = int(imms[pc])

            if op == 0xFF:
                break
            elif op == 0x00:
                pass
            elif op == 0x01:
                registers[dst] = registers[imm + 1]
            elif op == 0x02:
                registers[dst] = 1
            elif op == 0x03:
                registers[dst] = 0
            elif op == 0x04:
                registers[dst] = registers[s1]
            elif op == 0x10:
                registers[dst] = registers[s1] & registers[s2]
            elif op == 0x11:
                registers[dst] = registers[s1] | registers[s2]
            elif op == 0x12:
                registers[dst] = (~registers[s1]) & 1
            elif op == 0x13:
                registers[dst] = registers[s1] ^ registers[s2]
            elif op == 0x14:
                registers[dst] = (~(registers[s1] & registers[s2])) & 1
            elif op == 0x15:
                registers[dst] = (~(registers[s1] | registers[s2])) & 1
            elif op == 0x16:
                registers[dst] = ((~registers[s1]) | registers[s2]) & 1
            elif op == 0x17:
                registers[dst] = (~(registers[s1] ^ registers[s2])) & 1
            elif op == 0x20:
                registers[dst] = 1 if registers[s1] == registers[s2] else 0
            elif op == 0x21:
                registers[dst] = 1 if registers[s1] != registers[s2] else 0
            elif op == 0x22:
                registers[dst] = 1 if registers[s1] == imm else 0
            elif op == 0x30:
                registers[dst] = registers[s2] if registers[s1] else registers[imm]

        if registers[0]:
            byte_idx = tid >> 3
            bit_idx = tid & 7
            output[byte_idx] |= np.uint8(1 << bit_idx)

    return output


def count_sat(bitmap: npt.NDArray[np.uint8]) -> int:
    """Count number of satisfying assignments in bitmap."""
    return int(_unpackbits_little(bitmap).sum())


count_satisfying = count_sat


def get_satisfying_assignments(
    bitmap: npt.NDArray[np.uint8],
    num_vars: int,
    variable_names: list[str] | None = None,
) -> list[dict[str | int, bool]]:
    """Extract all satisfying assignments from bitmap.

    Args:
        bitmap: Packed output bitmap
        num_vars: Number of variables
        variable_names: Optional names for variables

    Returns:
        List of dicts mapping variable (name or index) to value
    """
    bits = _unpackbits_little(bitmap)
    assignments: list[dict[str | int, bool]] = []

    for i, sat in enumerate(bits[: 1 << num_vars]):
        if sat:
            if variable_names:
                assignment: dict[str | int, bool] = {
                    variable_names[v]: bool((i >> v) & 1) for v in range(num_vars)
                }
            else:
                assignment = {v: bool((i >> v) & 1) for v in range(num_vars)}
            assignments.append(assignment)

    return assignments


def _unpackbits_little(bitmap: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    """Return unpacked bits in little-endian bit order for each byte."""
    bits = np.unpackbits(bitmap)
    return bits.reshape(-1, 8)[:, ::-1].reshape(-1)


def warmup() -> None:
    """No-op warmup for reference backend."""
    pass
