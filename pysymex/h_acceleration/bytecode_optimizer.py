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

"""GPU Bytecode Optimizer - Advanced Optimization Passes.

Provides optimization passes for GPU bytecode:
- Constant Folding: Evaluate constant expressions at compile time
- Copy Propagation: Eliminate redundant COPY instructions
- Dead Code Elimination: Remove instructions whose results are unused
- Common Subexpression Elimination: Reuse previously computed values
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

import numpy as np

from pysymex.h_acceleration.bytecode import (
    INSTRUCTION_DTYPE,
    CompiledConstraint,
    Opcode,
)

__all__ = ["OptimizationStats", "optimize"]

_opt_cache: dict[tuple[int, int], tuple[CompiledConstraint, OptimizationStats]] = {}
_opt_lock = threading.Lock()


@dataclass
class OptimizationStats:
    """Statistics from optimization passes."""

    original_instructions: int = 0
    optimized_instructions: int = 0
    copies_eliminated: int = 0
    dead_code_eliminated: int = 0
    constants_folded: int = 0
    subexpressions_eliminated: int = 0

    @property
    def reduction_percent(self) -> float:
        if self.original_instructions == 0:
            return 0.0
        return 100.0 * (1 - self.optimized_instructions / self.original_instructions)


@dataclass
class OptInstruction:
    """Mutable instruction wrapper for optimization."""

    opcode: Opcode
    dst: int = 0
    src1: int = 0
    src2: int = 0
    flags: int = 0
    immediate: int = 0
    alive: bool = True

    @classmethod
    def from_numpy(cls, arr: np.void) -> OptInstruction:
        return cls(
            opcode=Opcode(int(arr["opcode"])),
            dst=int(arr["dst"]),
            src1=int(arr["src1"]),
            src2=int(arr["src2"]),
            flags=int(arr["flags"]),
            immediate=int(arr["immediate"]),
        )

    def to_tuple(self) -> tuple[int, int, int, int, int, int, int, int]:
        return (int(self.opcode), self.dst, self.src1, self.src2, self.flags, self.immediate, 0, 0)

    def writes(self) -> int | None:
        """Return the register written by this instruction, if any."""
        if self.opcode in (Opcode.NOP, Opcode.HALT):
            return None
        return self.dst

    def reads(self) -> list[int]:
        """Return the registers read by this instruction."""
        if self.opcode in (
            Opcode.LOAD_VAR,
            Opcode.LOAD_TRUE,
            Opcode.LOAD_FALSE,
            Opcode.NOP,
            Opcode.HALT,
        ):
            return []
        if self.opcode in (Opcode.NOT, Opcode.COPY, Opcode.EQ_CONST):
            return [self.src1]
        if self.opcode == Opcode.ITE:
            return [self.src1, self.src2, self.immediate]
        return [self.src1, self.src2]

    def canonical_key(self) -> str:
        """Return canonical representation for CSE."""
        if self.opcode == Opcode.LOAD_VAR:
            return f"{self.opcode.name}:{self.immediate}"
        if self.opcode in (Opcode.LOAD_TRUE, Opcode.LOAD_FALSE):
            return self.opcode.name
        if self.opcode in (Opcode.NOT, Opcode.COPY):
            return f"{self.opcode.name}:{self.src1}"
        if self.opcode == Opcode.ITE:
            return f"ITE:{self.src1}:{self.src2}:{self.immediate}"

        if self.opcode in (Opcode.AND, Opcode.OR, Opcode.XOR, Opcode.IFF, Opcode.NAND, Opcode.NOR):
            s1, s2 = sorted([self.src1, self.src2])
            return f"{self.opcode.name}:{s1}:{s2}"
        return f"{self.opcode.name}:{self.src1}:{self.src2}"


def optimize(constraint: CompiledConstraint) -> tuple[CompiledConstraint, OptimizationStats]:
    """Apply all optimization passes to a compiled constraint.

    Args:
        constraint: The constraint to optimize

    Returns:
        (optimized_constraint, stats)
    """

    cache_key = (constraint.source_hash, constraint.num_variables)
    with _opt_lock:
        if cache_key in _opt_cache:
            return _opt_cache[cache_key]

    stats = OptimizationStats(original_instructions=len(constraint.instructions))

    instrs = [OptInstruction.from_numpy(arr) for arr in constraint.instructions]

    changed = True
    iterations = 0
    max_iterations = 10

    while changed and iterations < max_iterations:
        changed = False
        iterations += 1

        if _pass_constant_folding(instrs, stats):
            changed = True

        if _pass_copy_propagation(instrs, stats):
            changed = True

        if _pass_cse(instrs, stats):
            changed = True

        if _pass_dce(instrs, stats):
            changed = True

    alive_instrs = [i for i in instrs if i.alive]

    if not alive_instrs or alive_instrs[-1].opcode != Opcode.HALT:
        alive_instrs.append(OptInstruction(opcode=Opcode.HALT))

    fixed_regs = set(range(constraint.num_variables + 1))
    reg_map = {r: r for r in fixed_regs}
    next_avail_reg = constraint.num_variables + 1

    for instr in alive_instrs:
        if instr.opcode not in (
            Opcode.LOAD_VAR,
            Opcode.LOAD_TRUE,
            Opcode.LOAD_FALSE,
            Opcode.NOP,
            Opcode.HALT,
        ):
            if instr.src1 not in reg_map:
                reg_map[instr.src1] = next_avail_reg
                next_avail_reg += 1
            instr.src1 = reg_map[instr.src1]

            if instr.opcode not in (Opcode.NOT, Opcode.COPY, Opcode.EQ_CONST):
                if instr.opcode == Opcode.ITE:
                    if instr.immediate not in reg_map:
                        reg_map[instr.immediate] = next_avail_reg
                        next_avail_reg += 1
                    instr.immediate = reg_map[instr.immediate]
                else:
                    if instr.src2 not in reg_map:
                        reg_map[instr.src2] = next_avail_reg
                        next_avail_reg += 1
                    instr.src2 = reg_map[instr.src2]

        written = instr.writes()
        if written is not None and written not in reg_map:
            reg_map[written] = next_avail_reg
            next_avail_reg += 1

        if written is not None:
            instr.dst = reg_map[written]

    stats.optimized_instructions = len(alive_instrs)

    instr_array = np.zeros(len(alive_instrs), dtype=INSTRUCTION_DTYPE)
    for i, instr in enumerate(alive_instrs):
        instr_array[i] = instr.to_tuple()

    result = CompiledConstraint(
        instructions=instr_array,
        num_variables=constraint.num_variables,
        register_count=next_avail_reg,
        source_hash=constraint.source_hash,
    )

    with _opt_lock:
        _opt_cache[cache_key] = (result, stats)

        while len(_opt_cache) > 256:
            oldest = next(iter(_opt_cache))
            del _opt_cache[oldest]

    return result, stats


def _pass_constant_folding(instrs: list[OptInstruction], stats: OptimizationStats) -> bool:
    """Fold constant expressions at compile time."""
    changed = False

    constants: dict[int, int] = {}

    for instr in instrs:
        if not instr.alive:
            continue

        if instr.opcode == Opcode.LOAD_TRUE:
            constants[instr.dst] = 0xFFFFFFFFFFFFFFFF
        elif instr.opcode == Opcode.LOAD_FALSE:
            constants[instr.dst] = 0
        elif instr.opcode == Opcode.COPY:
            if instr.src1 in constants:
                constants[instr.dst] = constants[instr.src1]
            else:
                constants.pop(instr.dst, None)
        elif instr.opcode == Opcode.NOT:
            if instr.src1 in constants:
                val = constants[instr.src1]
                result = ~val & 0xFFFFFFFFFFFFFFFF

                if result == 0xFFFFFFFFFFFFFFFF:
                    instr.opcode = Opcode.LOAD_TRUE
                    instr.src1 = 0
                else:
                    instr.opcode = Opcode.LOAD_FALSE
                    instr.src1 = 0
                constants[instr.dst] = result
                stats.constants_folded += 1
                changed = True
            else:
                constants.pop(instr.dst, None)
        elif instr.opcode == Opcode.AND:
            s1_const = instr.src1 in constants
            s2_const = instr.src2 in constants
            if s1_const and s2_const:
                result = constants[instr.src1] & constants[instr.src2]
                if result == 0xFFFFFFFFFFFFFFFF:
                    instr.opcode = Opcode.LOAD_TRUE
                else:
                    instr.opcode = Opcode.LOAD_FALSE
                instr.src1 = instr.src2 = 0
                constants[instr.dst] = result
                stats.constants_folded += 1
                changed = True
            elif s1_const:
                if constants[instr.src1] == 0:
                    instr.opcode = Opcode.LOAD_FALSE
                    instr.src1 = instr.src2 = 0
                    constants[instr.dst] = 0
                    stats.constants_folded += 1
                    changed = True
                elif constants[instr.src1] == 0xFFFFFFFFFFFFFFFF:
                    instr.opcode = Opcode.COPY
                    instr.src1 = instr.src2
                    instr.src2 = 0
                    constants.pop(instr.dst, None)
                    stats.constants_folded += 1
                    changed = True
                else:
                    constants.pop(instr.dst, None)
            elif s2_const:
                if constants[instr.src2] == 0:
                    instr.opcode = Opcode.LOAD_FALSE
                    instr.src1 = instr.src2 = 0
                    constants[instr.dst] = 0
                    stats.constants_folded += 1
                    changed = True
                elif constants[instr.src2] == 0xFFFFFFFFFFFFFFFF:
                    instr.opcode = Opcode.COPY
                    instr.src2 = 0
                    constants.pop(instr.dst, None)
                    stats.constants_folded += 1
                    changed = True
                else:
                    constants.pop(instr.dst, None)
            else:
                constants.pop(instr.dst, None)
        elif instr.opcode == Opcode.OR:
            s1_const = instr.src1 in constants
            s2_const = instr.src2 in constants
            if s1_const and s2_const:
                result = constants[instr.src1] | constants[instr.src2]
                if result == 0xFFFFFFFFFFFFFFFF:
                    instr.opcode = Opcode.LOAD_TRUE
                else:
                    instr.opcode = Opcode.LOAD_FALSE
                instr.src1 = instr.src2 = 0
                constants[instr.dst] = result
                stats.constants_folded += 1
                changed = True
            elif s1_const:
                if constants[instr.src1] == 0xFFFFFFFFFFFFFFFF:
                    instr.opcode = Opcode.LOAD_TRUE
                    instr.src1 = instr.src2 = 0
                    constants[instr.dst] = 0xFFFFFFFFFFFFFFFF
                    stats.constants_folded += 1
                    changed = True
                elif constants[instr.src1] == 0:
                    instr.opcode = Opcode.COPY
                    instr.src1 = instr.src2
                    instr.src2 = 0
                    constants.pop(instr.dst, None)
                    stats.constants_folded += 1
                    changed = True
                else:
                    constants.pop(instr.dst, None)
            elif s2_const:
                if constants[instr.src2] == 0xFFFFFFFFFFFFFFFF:
                    instr.opcode = Opcode.LOAD_TRUE
                    instr.src1 = instr.src2 = 0
                    constants[instr.dst] = 0xFFFFFFFFFFFFFFFF
                    stats.constants_folded += 1
                    changed = True
                elif constants[instr.src2] == 0:
                    instr.opcode = Opcode.COPY
                    instr.src2 = 0
                    constants.pop(instr.dst, None)
                    stats.constants_folded += 1
                    changed = True
                else:
                    constants.pop(instr.dst, None)
            else:
                constants.pop(instr.dst, None)
        else:
            if instr.writes() is not None:
                constants.pop(instr.dst, None)

    return changed


def _pass_copy_propagation(instrs: list[OptInstruction], stats: OptimizationStats) -> bool:
    """Propagate copy sources to eliminate redundant copies."""
    changed = False

    for i, instr in enumerate(instrs):
        if not instr.alive or instr.opcode != Opcode.COPY:
            continue

        if instr.dst == 0:
            has_later_r0_write = any(j.alive and j.writes() == 0 for j in instrs[i + 1 :])
            if not has_later_r0_write:
                continue

        src, dst = instr.src1, instr.dst

        for j in range(i + 1, len(instrs)):
            later = instrs[j]
            if not later.alive:
                continue

            if later.opcode not in (
                Opcode.LOAD_VAR,
                Opcode.LOAD_TRUE,
                Opcode.LOAD_FALSE,
                Opcode.NOP,
                Opcode.HALT,
            ):
                if later.src1 == dst:
                    later.src1 = src
                    changed = True
                if later.src2 == dst:
                    later.src2 = src
                    changed = True
                if later.opcode == Opcode.ITE and later.immediate == dst:
                    later.immediate = src
                    changed = True

            if later.writes() in (dst, src):
                break

    return changed


def _pass_cse(instrs: list[OptInstruction], stats: OptimizationStats) -> bool:
    """Eliminate common subexpressions."""
    changed = False

    available: dict[str, tuple[int, int]] = {}

    for i, instr in enumerate(instrs):
        if not instr.alive:
            continue

        if instr.opcode in (Opcode.NOP, Opcode.HALT):
            continue

        key = instr.canonical_key()

        if key in available:
            existing_reg, _ = available[key]

            instr.opcode = Opcode.COPY
            instr.src1 = existing_reg
            instr.src2 = 0
            instr.immediate = 0
            stats.subexpressions_eliminated += 1
            changed = True
        else:
            if instr.writes() is not None:
                available[key] = (instr.dst, i)

        written = instr.writes()
        if written is not None:
            to_remove = [k for k, (reg, _) in available.items() if reg == written]
            for k in to_remove:
                del available[k]

    return changed


def _pass_dce(instrs: list[OptInstruction], stats: OptimizationStats) -> bool:
    """Eliminate dead code (instructions whose results are never used)."""
    changed = False

    live: set[int] = {0}

    for instr in reversed(instrs):
        if instr.alive and instr.opcode == Opcode.COPY and instr.dst == 0:
            live.add(instr.src1)
            break
        if instr.alive and instr.writes() == 0:
            break

    for instr in reversed(instrs):
        if not instr.alive:
            continue

        if instr.opcode == Opcode.HALT:
            continue

        written = instr.writes()
        if written is not None:
            if written in live:
                if written != 0:
                    live.discard(written)
                for src in instr.reads():
                    live.add(src)
            else:
                instr.alive = False
                stats.dead_code_eliminated += 1
                changed = True
        else:
            if instr.opcode == Opcode.NOP:
                instr.alive = False
                changed = True

    return changed


def clear_cache() -> None:
    """Clear the optimization cache."""
    global _opt_cache
    with _opt_lock:
        _opt_cache.clear()
