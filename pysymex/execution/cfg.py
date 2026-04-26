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

"""Control Flow Graph (CFG) construction from bytecode.

This module builds an explicit CFG from Python bytecode to enable
static analysis and better path exploration strategies.
"""

from __future__ import annotations

import dis
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass
class BasicBlock:
    """A basic block in the CFG - a sequence of instructions with single entry/exit."""

    start_pc: int
    end_pc: int
    instructions: list[dis.Instruction]
    successors: list[int]
    is_branch: bool = False
    is_return: bool = False


@dataclass
class ControlFlowGraph:
    """Explicit CFG for a function's bytecode."""

    blocks: dict[int, BasicBlock]
    entry_pc: int
    exit_pcs: set[int]

    def get_block_for_pc(self, pc: int) -> BasicBlock | None:
        """Get the basic block containing the given PC."""
        for block in self.blocks.values():
            if block.start_pc <= pc <= block.end_pc:
                return block
        return None

    def get_successors(self, pc: int) -> list[int]:
        """Get successor PCs for the given PC."""
        block = self.get_block_for_pc(pc)
        return block.successors if block else []


def _jump_target(instr: dis.Instruction) -> int | None:
    """Return integer jump target offset when available."""
    argval = instr.argval
    if isinstance(argval, int):
        return argval
    return None


def build_cfg(instructions: Iterable[dis.Instruction]) -> ControlFlowGraph:
    """Build an explicit CFG from bytecode instructions.

    Args:
        instructions: Iterable of dis.Instruction objects

    Returns:
        ControlFlowGraph with explicit basic blocks and edges
    """
    instr_list = list(instructions)
    if not instr_list:
        return ControlFlowGraph(blocks={}, entry_pc=0, exit_pcs=set())

    branch_targets: set[int] = set()
    block_leaders: set[int] = {0}

    for instr in instr_list:
        pc = instr.offset
        if instr.opname in (
            "JUMP_FORWARD",
            "JUMP_ABSOLUTE",
            "JUMP",
            "POP_JUMP_FORWARD_IF_FALSE",
            "POP_JUMP_FORWARD_IF_TRUE",
            "POP_JUMP_ABSOLUTE_IF_FALSE",
            "POP_JUMP_ABSOLUTE_IF_TRUE",
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_IF_TRUE",
            "POP_JUMP_BACKWARD_IF_FALSE",
            "POP_JUMP_BACKWARD_IF_TRUE",
            "FOR_ITER",
            "SEND",
            "SETUP_LOOP",
            "SETUP_EXCEPT",
            "SETUP_FINALLY",
        ):
            target = _jump_target(instr)
            if target is not None:
                branch_targets.add(target)
                block_leaders.add(target)
            next_pc = pc + 2
            if next_pc < len(instr_list):
                block_leaders.add(next_pc)

        if instr.opname in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"):
            block_leaders.add(pc + 2)

    blocks: dict[int, BasicBlock] = {}
    sorted_leaders = sorted(block_leaders)

    for i, leader_pc in enumerate(sorted_leaders):
        next_leader = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else None
        block_instrs: list[dis.Instruction] = []
        successors: list[int] = []
        is_branch = False
        is_return = False

        for instr in instr_list:
            if instr.offset < leader_pc:
                continue
            if next_leader is not None and instr.offset >= next_leader:
                break
            block_instrs.append(instr)

            if instr.opname in ("JUMP_FORWARD", "JUMP_ABSOLUTE", "JUMP"):
                is_branch = True
                target = _jump_target(instr)
                if target is not None:
                    successors.append(target)
            elif instr.opname in (
                "POP_JUMP_FORWARD_IF_FALSE",
                "POP_JUMP_FORWARD_IF_TRUE",
                "POP_JUMP_ABSOLUTE_IF_FALSE",
                "POP_JUMP_ABSOLUTE_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_BACKWARD_IF_FALSE",
                "POP_JUMP_BACKWARD_IF_TRUE",
            ):
                is_branch = True
                target = _jump_target(instr)
                if target is not None:
                    successors.append(target)
                    next_pc = instr.offset + 2
                    if next_pc < len(instr_list):
                        successors.append(next_pc)
            elif instr.opname in ("FOR_ITER", "SEND"):
                is_branch = True
                target = _jump_target(instr)
                if target is not None:
                    successors.append(target)
                    next_pc = instr.offset + 2
                    if next_pc < len(instr_list):
                        successors.append(next_pc)
            elif instr.opname in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"):
                is_return = True
            elif not is_branch and not is_return:
                next_pc = instr.offset + 2
                if next_pc < len(instr_list):
                    successors.append(next_pc)

        if block_instrs:
            start_pc = block_instrs[0].offset
            end_pc = block_instrs[-1].offset
            blocks[start_pc] = BasicBlock(
                start_pc=start_pc,
                end_pc=end_pc,
                instructions=block_instrs,
                successors=successors,
                is_branch=is_branch,
                is_return=is_return,
            )

    exit_pcs = {
        block.start_pc for block in blocks.values() if block.is_return or not block.successors
    }

    return ControlFlowGraph(blocks=blocks, entry_pc=0, exit_pcs=exit_pcs)
