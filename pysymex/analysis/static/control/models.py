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

"""Core data structures for the control-flow graph: blocks, edges, and graph."""

from __future__ import annotations

import dis
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum, auto

from pysymex.analysis.static.types import TypeState
from pysymex.core.bytecode import get_starts_line

get_line_number = get_starts_line


class EdgeKind(Enum):
    """Classification of edges between ``BasicBlock`` nodes in the CFG."""

    SEQUENTIAL = auto()
    BRANCH_TRUE = auto()
    BRANCH_FALSE = auto()
    JUMP = auto()
    EXCEPTION = auto()
    RETURN = auto()
    CALL = auto()
    YIELD = auto()
    RAISE = auto()
    LOOP_BACK = auto()
    LOOP_EXIT = auto()


@dataclass
class BasicBlock:
    """A maximal straight-line sequence of bytecode instructions in a CFG.

    Maintains predecessor/successor sets with typed edges, source line
    numbers, entry/exit flags, loop-header and exception-handler markers,
    optional type-inference states, and dominator tree links.
    """

    id: int
    start_pc: int
    end_pc: int
    instructions: list[dis.Instruction] = field(default_factory=list[dis.Instruction])
    line_numbers: set[int] = field(default_factory=set[int])
    predecessors: set[int] = field(default_factory=set[int])
    successors: set[int] = field(default_factory=set[int])
    successor_edges: dict[int, EdgeKind] = field(default_factory=dict[int, EdgeKind])
    is_entry: bool = False
    is_exit: bool = False
    is_loop_header: bool = False
    is_exception_handler: bool = False
    entry_state: TypeState | None = None
    exit_state: TypeState | None = None
    immediate_dominator: int | None = None
    dominated_blocks: set[int] = field(default_factory=set[int])

    @property
    def block_id(self) -> int:
        """Alias for id, used by some analysis passes."""
        return self.id

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash(self.id)

    def add_instruction(self, instr: dis.Instruction) -> None:
        """Append *instr*, update line numbers, and extend the block's PC range."""
        self.instructions.append(instr)
        line_num = get_line_number(instr)
        if line_num is not None:
            self.line_numbers.add(line_num)
        self.end_pc = instr.offset

    def add_successor(self, block_id: int, edge_kind: EdgeKind) -> None:
        """Register *block_id* as a successor with edge type *edge_kind*."""
        self.successors.add(block_id)
        self.successor_edges[block_id] = edge_kind

    def get_terminator(self) -> dis.Instruction | None:
        """Return the last instruction in this block, or ``None`` if empty."""
        if self.instructions:
            return self.instructions[-1]
        return None

    def is_conditional(self) -> bool:
        """Return ``True`` if the terminator is a conditional jump or loop iterator."""
        term = self.get_terminator()
        if term:
            op = term.opname
            return (
                op.startswith("POP_JUMP_")
                or op.startswith("JUMP_IF_")
                or op in {"FOR_ITER", "SEND"}
            )
        return False

    def __repr__(self) -> str:
        """Return string representation of BasicBlock.

        Returns:
            str: String detailing basic block ID and PC bounds.
        """
        return f"BasicBlock({self.id}, pc={self.start_pc}-{self.end_pc})"


@dataclass
class ControlFlowGraph:
    """Control-flow graph for a single function.

    Stores blocks keyed by integer ID, a PC → block lookup, dominator
    and post-dominator sets, loop metadata (headers, back edges,
    natural loop bodies), and construction warnings.
    """

    blocks: dict[int, BasicBlock] = field(default_factory=dict[int, BasicBlock])
    entry_block_id: int = 0
    exit_block_ids: set[int] = field(default_factory=set[int])
    pc_to_block: dict[int, int] = field(default_factory=dict[int, int])
    loop_headers: set[int] = field(default_factory=set[int])
    loop_back_edges: set[tuple[int, int]] = field(default_factory=set[tuple[int, int]])
    natural_loops: dict[int, set[int]] = field(default_factory=dict[int, set[int]])
    dominators: dict[int, set[int]] = field(default_factory=dict[int, set[int]])
    post_dominators: dict[int, set[int]] = field(default_factory=dict[int, set[int]])
    construction_warnings: list[str] = field(default_factory=list[str])

    @property
    def entry(self) -> BasicBlock | None:
        """Return the entry ``BasicBlock``, or ``None`` if the graph is empty."""
        return self.blocks.get(self.entry_block_id)

    def add_block(self, block: BasicBlock) -> None:
        """Register *block* and map its PC range to its ID."""
        self.blocks[block.id] = block
        for pc in range(block.start_pc, block.end_pc + 1):
            self.pc_to_block[pc] = block.id

    def get_block(self, block_id: int) -> BasicBlock | None:
        """Return the block with *block_id*, or ``None``."""
        return self.blocks.get(block_id)

    def get_block_at_pc(self, pc: int) -> BasicBlock | None:
        """Return the block whose PC range contains *pc*, or ``None``."""
        block_id = self.pc_to_block.get(pc)
        if block_id is not None:
            return self.blocks.get(block_id)
        return None

    def get_predecessors(self, block_id: int) -> set[int]:
        """Return the predecessor block IDs of *block_id*."""
        block = self.blocks.get(block_id)
        if block:
            return block.predecessors
        return set()

    def get_successors(self, block_id: int) -> set[int]:
        """Return the successor block IDs of *block_id*."""
        block = self.blocks.get(block_id)
        if block:
            return block.successors
        return set()

    def is_reachable(self, block_id: int) -> bool:
        """Return ``True`` if *block_id* is reachable from the entry (has dominator data)."""
        return block_id in self.dominators

    def dominates(self, dominator_id: int, dominated_id: int) -> bool:
        """Return ``True`` if *dominator_id* dominates *dominated_id* in the dominator tree."""
        dom_set = self.dominators.get(dominated_id, ())
        return dominator_id in dom_set

    def get_immediate_dominator(self, block_id: int) -> int | None:
        """Return the immediate dominator of *block_id*, or ``None`` for the entry."""
        block = self.blocks.get(block_id)
        if block:
            return block.immediate_dominator
        return None

    def is_loop_header(self, block_id: int) -> bool:
        """Return ``True`` if *block_id* is a natural-loop header."""
        return block_id in self.loop_headers

    def get_loop_body(self, header_id: int) -> set[int]:
        """Return the set of block IDs forming the natural loop headed by *header_id*."""
        res = self.natural_loops.get(header_id)
        return res if res is not None else set()

    def iter_blocks_forward(self) -> Iterable[BasicBlock]:
        """Yield blocks in topological (entry → exit) order, skipping loop back-edges."""
        visited: set[int] = set()
        result: list[BasicBlock] = []

        def visit(block_id: int) -> None:
            """Visit."""
            if block_id in visited:
                return
            visited.add(block_id)
            block = self.blocks.get(block_id)
            if not block:
                return
            for pred_id in sorted(block.predecessors):
                if pred_id not in visited:
                    if (pred_id, block_id) not in self.loop_back_edges:
                        visit(pred_id)
            result.append(block)
            for succ_id in sorted(block.successors):
                visit(succ_id)

        visit(self.entry_block_id)
        return result

    def iter_blocks_reverse(self) -> Iterable[BasicBlock]:
        """Yield blocks in reverse topological (exit → entry) order."""
        return reversed(list(self.iter_blocks_forward()))


__all__ = ["BasicBlock", "ControlFlowGraph", "EdgeKind", "get_line_number"]
