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

"""Control Flow Graph construction from Python bytecode.

Provides ``CFGBuilder``, which builds a ``ControlFlowGraph`` from a
``CodeType`` by classifying opcodes into leader-inducing categories
(jumps, conditionals, loop ops, returns, raises, exception setup),
partitioning instructions into ``BasicBlock`` nodes, adding typed
edges (``EdgeKind``), computing dominators, and detecting natural loops.
"""

from __future__ import annotations

import dis
import types
from collections.abc import Sequence

from pysymex.analysis.static.control.models import BasicBlock as _BasicBlock
from pysymex.analysis.static.control.models import ControlFlowGraph as _ControlFlowGraph
from pysymex.analysis.static.control.models import EdgeKind as _EdgeKind
from pysymex.analysis.static.control.dominators import compute_dominators
from pysymex.analysis.static.control.protocols import BytecodeWithExceptionEntries
from pysymex.analysis.static.control.protocols import (
    ExceptionEntryProtocol as _ExceptionEntryProtocol,
)
from pysymex.core.cache import get_instructions as cached_get_instructions
from pysymex.logger import get_logger

logger = get_logger(__name__)

__all__ = [
    "CFGBuilder",
]


class CFGBuilder:
    """Builds a control-flow graph from a ``CodeType`` or instruction list.

    Construction pipeline:
    1. Extract leader offsets (block boundaries) from jump targets,
       exception entries, and terminator fall-throughs.
    2. Partition instructions into ``BasicBlock`` objects.
    3. Add inter-block edges classified by ``EdgeKind``.
    4. Compute forward dominators and immediate dominators.
    5. Identify natural loops via ``LoopDetector``.
    """

    JUMP_OPS = {
        "JUMP_FORWARD",
        "JUMP_BACKWARD",
        "JUMP_ABSOLUTE",
        "JUMP_BACKWARD_NO_INTERRUPT",
        "JUMP",
        "JUMP_NO_INTERRUPT",
    }
    CONDITIONAL_JUMP_OPS = {
        "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_IF_NONE",
        "POP_JUMP_IF_NOT_NONE",
        "POP_JUMP_FORWARD_IF_TRUE",
        "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_FORWARD_IF_NONE",
        "POP_JUMP_FORWARD_IF_NOT_NONE",
        "POP_JUMP_BACKWARD_IF_TRUE",
        "POP_JUMP_BACKWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_NONE",
        "POP_JUMP_BACKWARD_IF_NOT_NONE",
        "JUMP_IF_TRUE_OR_POP",
        "JUMP_IF_FALSE_OR_POP",
        "JUMP_IF_NOT_EXC_MATCH",
    }
    LOOP_OPS = {
        "FOR_ITER",
        "SEND",
        "GET_ITER",
        "GET_AITER",
        "GET_ANEXT",
    }
    RETURN_OPS = {
        "RETURN_VALUE",
        "RETURN_CONST",
        "RETURN_GENERATOR",
    }
    RAISE_OPS = {
        "RAISE_VARARGS",
        "RERAISE",
    }
    EXCEPTION_OPS = {
        "SETUP_FINALLY",
        "POP_EXCEPT",
        "PUSH_EXC_INFO",
        "CHECK_EXC_MATCH",
        "CLEANUP_THROW",
    }

    def build(self, code: types.CodeType) -> _ControlFlowGraph:
        """Build a ``ControlFlowGraph`` from a compiled code object.

        Extracts instructions via ``cached_get_instructions`` and, when
        available, the Python 3.11+ exception table.  Construction
        warnings (e.g. inaccessible exception tables) are recorded on
        the returned graph.
        """
        instructions = cached_get_instructions(code)
        if not instructions:
            return _ControlFlowGraph()

        exception_entries: list[_ExceptionEntryProtocol] = []
        construction_warnings: list[str] = []
        if hasattr(code, "co_exceptiontable"):
            try:
                bytecode_obj = dis.Bytecode(code)
                if isinstance(bytecode_obj, BytecodeWithExceptionEntries):
                    exception_entries = list(bytecode_obj.exception_entries)
            except Exception as exc:
                warning = (
                    "Failed to extract bytecode exception table for CFG: "
                    f"{type(exc).__name__}: {exc}"
                )
                construction_warnings.append(warning)
                logger.warning(warning, exc_info=True)

        cfg = self._build_from_params(instructions, exception_entries)
        cfg.construction_warnings.extend(construction_warnings)
        return cfg

    def build_from_instructions(self, instructions: Sequence[dis.Instruction]) -> _ControlFlowGraph:
        """Build a ``ControlFlowGraph`` from pre-extracted instructions."""
        return self._build_from_params(instructions, [])

    def _build_from_params(
        self,
        instructions: Sequence[dis.Instruction],
        exception_entries: list[_ExceptionEntryProtocol],
    ) -> _ControlFlowGraph:
        """Construct a CFG from instructions and exception entries (shared implementation)."""
        leaders = self._find_leaders(instructions, exception_entries)
        cfg = self._create_blocks(instructions, leaders)
        self._add_edges(cfg, instructions, exception_entries)
        compute_dominators(cfg)
        self._identify_loops(cfg, instructions)
        return cfg

    def _find_leaders(
        self,
        instructions: Sequence[dis.Instruction],
        exception_entries: list[_ExceptionEntryProtocol] | None = None,
    ) -> set[int]:
        """Identify leader offsets that start new basic blocks.

        Leaders include: first instruction, jump/conditional-jump targets,
        fall-through instructions after terminators, exception handler
        targets, and instructions after exception setup opcodes.
        """
        leaders: set[int] = set()
        if instructions:
            leaders.add(instructions[0].offset)

        if exception_entries:
            for entry in exception_entries:
                leaders.add(entry.target)

        for i, instr in enumerate(instructions):
            if instr.opname in self.JUMP_OPS | self.CONDITIONAL_JUMP_OPS | self.LOOP_OPS:
                target = instr.argval
                if isinstance(target, int):
                    leaders.add(target)
                if instr.opname in self.CONDITIONAL_JUMP_OPS | self.LOOP_OPS:
                    if i + 1 < len(instructions):
                        leaders.add(instructions[i + 1].offset)

            if instr.opname in {"SETUP_FINALLY", "SETUP_EXCEPT", "SETUP_WITH", "SETUP_ASYNC_WITH"}:
                target = instr.argval
                if isinstance(target, int):
                    leaders.add(target)

            if instr.opname in self.JUMP_OPS | self.RETURN_OPS | self.RAISE_OPS:
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].offset)
            if instr.opname in self.EXCEPTION_OPS:
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].offset)
        return leaders

    def _create_blocks(
        self,
        instructions: Sequence[dis.Instruction],
        leaders: set[int],
    ) -> _ControlFlowGraph:
        """Partition instructions into ``BasicBlock`` objects based on leader offsets.

        Also identifies the entry block and marks return blocks as exits.
        """
        cfg = _ControlFlowGraph()
        if not instructions:
            return cfg
        current_block: _BasicBlock | None = None
        block_id = 0
        for instr in instructions:
            if instr.offset in leaders:
                if current_block:
                    cfg.add_block(current_block)
                current_block = _BasicBlock(
                    id=block_id,
                    start_pc=instr.offset,
                    end_pc=instr.offset,
                )
                block_id += 1
            if current_block:
                current_block.add_instruction(instr)
        if current_block:
            cfg.add_block(current_block)
        if cfg.blocks:
            first_block = cfg.blocks[0]
            first_block.is_entry = True
            cfg.entry_block_id = first_block.id
            for block in cfg.blocks.values():
                term = block.get_terminator()
                if term and term.opname in self.RETURN_OPS:
                    block.is_exit = True
                    cfg.exit_block_ids.add(block.id)
        return cfg

    def _add_edges(
        self,
        cfg: _ControlFlowGraph,
        instructions: Sequence[dis.Instruction],
        exception_entries: list[_ExceptionEntryProtocol] | None = None,
    ) -> None:
        """Add typed inter-block edges (sequential, branch, exception, loop) to the CFG.

        Walks each block's terminator to determine jump, conditional,
        loop, return/raise, and setup targets.  Also connects blocks
        covered by exception table entries to their handler blocks.
        """
        pc_to_idx = {instr.offset: i for i, instr in enumerate(instructions)}
        for block in cfg.blocks.values():
            term = block.get_terminator()
            if not term:
                continue

            if term.opname in self.JUMP_OPS:
                target = term.argval
                if isinstance(target, int):
                    target_block = cfg.get_block_at_pc(target)
                    if target_block:
                        block.add_successor(target_block.id, _EdgeKind.JUMP)
                        target_block.predecessors.add(block.id)
            elif term.opname in self.CONDITIONAL_JUMP_OPS:
                target = term.argval
                if isinstance(target, int):
                    target_block = cfg.get_block_at_pc(target)
                    if target_block:
                        if "TRUE" in term.opname or "NOT_NONE" in term.opname:
                            block.add_successor(target_block.id, _EdgeKind.BRANCH_TRUE)
                        else:
                            block.add_successor(target_block.id, _EdgeKind.BRANCH_FALSE)
                        target_block.predecessors.add(block.id)

                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        if "TRUE" in term.opname or "NOT_NONE" in term.opname:
                            block.add_successor(next_block.id, _EdgeKind.BRANCH_FALSE)
                        else:
                            block.add_successor(next_block.id, _EdgeKind.BRANCH_TRUE)
                        next_block.predecessors.add(block.id)
            elif term.opname in self.LOOP_OPS:
                target = term.argval
                if isinstance(target, int):
                    target_block = cfg.get_block_at_pc(target)
                    if target_block:
                        block.add_successor(target_block.id, _EdgeKind.LOOP_EXIT)
                        target_block.predecessors.add(block.id)

                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        block.add_successor(next_block.id, _EdgeKind.SEQUENTIAL)
                        next_block.predecessors.add(block.id)
            elif term.opname in self.RETURN_OPS | self.RAISE_OPS:
                pass

            elif term.opname in {"SETUP_FINALLY", "SETUP_EXCEPT", "SETUP_WITH", "SETUP_ASYNC_WITH"}:
                target = term.argval
                if isinstance(target, int):
                    target_block = cfg.get_block_at_pc(target)
                    if target_block:
                        block.add_successor(target_block.id, _EdgeKind.EXCEPTION)
                        target_block.predecessors.add(block.id)
                        target_block.is_exception_handler = True

                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        block.add_successor(next_block.id, _EdgeKind.SEQUENTIAL)
                        next_block.predecessors.add(block.id)
            else:
                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        block.add_successor(next_block.id, _EdgeKind.SEQUENTIAL)
                        next_block.predecessors.add(block.id)

        if exception_entries:
            for entry in exception_entries:
                handler_block = cfg.get_block_at_pc(entry.target)
                if not handler_block:
                    continue
                handler_block.is_exception_handler = True

                for block in cfg.blocks.values():
                    if block.start_pc < entry.end and block.end_pc >= entry.start:
                        if handler_block.id not in block.successors:
                            block.add_successor(handler_block.id, _EdgeKind.EXCEPTION)
                            handler_block.predecessors.add(block.id)

    def _identify_loops(
        self, cfg: _ControlFlowGraph, instructions: Sequence[dis.Instruction]
    ) -> None:
        """Detect natural loops in *cfg* and populate loop headers, back edges, and body sets."""
        from pysymex.analysis.static.loops.detector import LoopDetector

        detector = LoopDetector()
        entry_pc = instructions[0].offset if instructions else cfg.entry_block_id
        loops = detector.analyze_cfg(list(instructions), entry_pc=entry_pc)

        for loop in loops:
            header_block = cfg.get_block_at_pc(loop.header_pc)
            back_block = cfg.get_block_at_pc(loop.back_edge_pc)

            if not header_block or not back_block:
                continue

            cfg.loop_headers.add(header_block.id)
            cfg.loop_back_edges.add((back_block.id, header_block.id))

            # Map loop body PCs to block IDs
            body_block_ids: set[int] = set()
            for pc in loop.body_pcs:
                block = cfg.get_block_at_pc(pc)
                if block is not None:
                    body_block_ids.add(block.id)
            cfg.natural_loops[header_block.id] = body_block_ids | {header_block.id}

            header_block.is_loop_header = True
            back_block.successor_edges[header_block.id] = _EdgeKind.LOOP_BACK
