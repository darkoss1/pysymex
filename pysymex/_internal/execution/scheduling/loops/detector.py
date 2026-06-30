# pysymex: python symbolic execution & formal verification
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

"""Detect natural loops in bytecode by identifying back edges and computing loop bodies."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.scheduling.loops.cfg import (
    build_cfg,
    compute_dominators,
    find_back_edges,
)
from pysymex._internal.execution.scheduling.loops.info import build_loop_info, compute_nesting

if TYPE_CHECKING:
    import dis

    from pysymex._internal.execution.scheduling.loops.types import LoopInfo


class LoopDetector:
    """Detects loops in bytecode via control-flow graph analysis."""

    def __init__(self) -> None:
        self._loops: list[LoopInfo] = []
        self._back_edges: list[tuple[int, int]] = []

    def analyze_cfg(
        self,
        instructions: list[dis.Instruction],
        entry_pc: int = 0,
    ) -> list[LoopInfo]:
        """Analyze control flow graph to detect loops."""
        self._loops = []
        self._back_edges = []
        cfg = build_cfg(instructions)
        dominators = compute_dominators(cfg, entry_pc)
        self._back_edges = find_back_edges(cfg, dominators)
        instruction_by_offset = {instruction.offset: instruction for instruction in instructions}
        for from_pc, to_pc in self._back_edges:
            loop = build_loop_info(cfg, from_pc, to_pc)
            _canonicalize_for_loop_cleanup(instruction_by_offset, loop)
            self._loops.append(loop)
        compute_nesting(self._loops)
        return self._loops

    @property
    def loops(self) -> list[LoopInfo]:
        """Expose detected loops for tests and formal checks."""
        return self._loops

    def get_loop_at(self, pc: int) -> LoopInfo | None:
        """Get the innermost loop containing a PC."""
        candidates = [loop for loop in self._loops if loop.contains_pc(pc)]
        if not candidates:
            return None
        return max(candidates, key=lambda loop: loop.nesting_depth)


def _canonicalize_for_loop_cleanup(
    instruction_by_offset: dict[int, dis.Instruction],
    loop: LoopInfo,
) -> None:
    """Keep bytecode cleanup opcodes out of ``FOR_ITER`` loop bodies.

    Python 3.11 exits a ``for`` loop by jumping to ``POP_TOP``; Python 3.12+
    jumps to ``END_FOR``. CFG back-edge reconstruction can otherwise classify
    that cleanup opcode as part of the natural loop body, which makes widened
    loop exits skip past the bytecode-level cleanup and corrupts the simulated
    stack shape.
    """
    header = instruction_by_offset.get(loop.header_pc)
    if header is None or header.opname != "FOR_ITER":
        return
    if not isinstance(header.argval, int):
        return
    exit_pc = header.argval
    exit_instruction = instruction_by_offset.get(exit_pc)
    if exit_instruction is None:
        return
    if exit_instruction.opname not in {"POP_TOP", "END_FOR"}:
        return
    loop.body_pcs.discard(exit_pc)
    loop.exit_pcs.add(exit_pc)
