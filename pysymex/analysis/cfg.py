"""
Control Flow Graph infrastructure for pysymex.

Provides:
- Basic block representation
- Control flow graph construction from bytecode
- Dominator computation
- Natural loop detection
"""

from __future__ import annotations

import dis
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum, auto

from pysymex._compat import get_starts_line
from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

from .type_inference import TypeState

_get_line_number = get_starts_line

__all__ = [
    "BasicBlock",
    "CFGBuilder",
    "ControlFlowGraph",
    "EdgeKind",
]


class EdgeKind(Enum):
    """Types of CFG edges."""

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
    """
    A basic block in the control flow graph.

    A basic block is a straight-line sequence of instructions with:
    - One entry point (first instruction)
    - One exit point (last instruction)
    - No internal branches or targets
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
        """Hash."""
        """Return the hash value of the object."""
        return hash(self.id)

    def add_instruction(self, instr: dis.Instruction) -> None:
        """Add an instruction to this block."""
        self.instructions.append(instr)
        line_num = _get_line_number(instr)
        if line_num is not None:
            self.line_numbers.add(line_num)
        self.end_pc = instr.offset

    def add_successor(self, block_id: int, edge_kind: EdgeKind) -> None:
        """Add a successor block."""
        self.successors.add(block_id)
        self.successor_edges[block_id] = edge_kind

    def get_terminator(self) -> dis.Instruction | None:
        """Get the terminating instruction of this block."""
        if self.instructions:
            return self.instructions[-1]
        return None

    def is_conditional(self) -> bool:
        """Check if this block ends with a conditional branch."""
        term = self.get_terminator()
        if term:
            return term.opname in {
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
                "JUMP_IF_TRUE_OR_POP",
                "JUMP_IF_FALSE_OR_POP",
                "FOR_ITER",
                "SEND",
            }
        return False

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        return f"BasicBlock({self .id }, pc={self .start_pc }-{self .end_pc })"


@dataclass
class ControlFlowGraph:
    """
    Control flow graph for a function.

    Provides:
    - Basic block identification
    - Edge analysis
    - Loop detection
    - Dominator computation
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

    @property
    def entry(self) -> BasicBlock | None:
        """Get the entry basic block."""
        return self.blocks.get(self.entry_block_id)

    def add_block(self, block: BasicBlock) -> None:
        """Add a basic block."""
        self.blocks[block.id] = block
        for pc in range(block.start_pc, block.end_pc + 1):
            self.pc_to_block[pc] = block.id

    def get_block(self, block_id: int) -> BasicBlock | None:
        """Get a block by ID."""
        return self.blocks.get(block_id)

    def get_block_at_pc(self, pc: int) -> BasicBlock | None:
        """Get the block containing a given PC."""
        block_id = self.pc_to_block.get(pc)
        if block_id is not None:
            return self.blocks.get(block_id)
        return None

    def get_predecessors(self, block_id: int) -> set[int]:
        """Get predecessor block IDs."""
        block = self.blocks.get(block_id)
        if block:
            return block.predecessors
        return set()

    def get_successors(self, block_id: int) -> set[int]:
        """Get successor block IDs."""
        block = self.blocks.get(block_id)
        if block:
            return block.successors
        return set()

    def is_reachable(self, block_id: int) -> bool:
        """Check if a block is reachable from entry."""
        return block_id in self.dominators

    def dominates(self, dominator_id: int, dominated_id: int) -> bool:
        """Check if dominator dominates dominated."""
        dom_set = self.dominators.get(dominated_id, set())
        return dominator_id in dom_set

    def get_immediate_dominator(self, block_id: int) -> int | None:
        """Get the immediate dominator of a block."""
        block = self.blocks.get(block_id)
        if block:
            return block.immediate_dominator
        return None

    def is_loop_header(self, block_id: int) -> bool:
        """Check if a block is a loop header."""
        return block_id in self.loop_headers

    def get_loop_body(self, header_id: int) -> set[int]:
        """Get blocks in a loop's body."""
        return self.natural_loops.get(header_id, set())

    def iter_blocks_forward(self) -> Iterable[BasicBlock]:
        """Iterate blocks in forward order (entry to exit)."""
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
            for pred_id in block.predecessors:
                if pred_id not in visited:
                    if (pred_id, block_id) not in self.loop_back_edges:
                        visit(pred_id)
            result.append(block)
            for succ_id in block.successors:
                visit(succ_id)

        visit(self.entry_block_id)
        return result

    def iter_blocks_reverse(self) -> Iterable[BasicBlock]:
        """Iterate blocks in reverse order (exit to entry)."""
        return reversed(list(self.iter_blocks_forward()))


class CFGBuilder:
    """Builds a control flow graph from bytecode."""

    JUMP_OPS = {
        "JUMP_FORWARD",
        "JUMP_BACKWARD",
        "JUMP_ABSOLUTE",
        "JUMP_BACKWARD_NO_INTERRUPT",
    }
    CONDITIONAL_JUMP_OPS = {
        "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_IF_NONE",
        "POP_JUMP_IF_NOT_NONE",
        "JUMP_IF_TRUE_OR_POP",
        "JUMP_IF_FALSE_OR_POP",
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

    def build(self, code: object) -> ControlFlowGraph:
        """Build CFG from a code object."""
        instructions = _cached_get_instructions(code)
        if not instructions:
            return ControlFlowGraph()
        
        exception_entries = []
        if hasattr(code, "co_exceptiontable"):
            try:
                exception_entries = list(dis.Bytecode(code).exception_entries)
            except Exception:
                pass

        return self._build_from_params(instructions, exception_entries)

    def build_from_instructions(self, instructions: Sequence[dis.Instruction]) -> ControlFlowGraph:
        """Build CFG from a list of instructions (useful when code object is unavailable)."""
        return self._build_from_params(instructions, [])

    def _build_from_params(
        self,
        instructions: Sequence[dis.Instruction],
        exception_entries: list[dis.ExceptionTableEntry],
    ) -> ControlFlowGraph:
        """Internal helper to build CFG from components."""
        leaders = self._find_leaders(instructions, exception_entries)
        cfg = self._create_blocks(instructions, leaders)
        self._add_edges(cfg, instructions, exception_entries)
        self._compute_dominators(cfg)
        self._identify_loops(cfg)
        return cfg

    def _find_leaders(
        self, 
        instructions: Sequence[dis.Instruction],
        exception_entries: list[dis.ExceptionTableEntry] = None
    ) -> set[int]:
        """Find leader instructions that start basic blocks."""
        leaders: set[int] = set()
        if instructions:
            leaders.add(instructions[0].offset)
        
        # Add targets of exception handlers as leaders
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
            
            # For older Python: SETUP_FINALLY and friends have jump targets
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
    ) -> ControlFlowGraph:
        """Create basic blocks from instructions and leaders."""
        cfg = ControlFlowGraph()
        if not instructions:
            return cfg
        current_block: BasicBlock | None = None
        block_id = 0
        for instr in instructions:
            if instr.offset in leaders:
                if current_block:
                    cfg.add_block(current_block)
                current_block = BasicBlock(
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
        cfg: ControlFlowGraph,
        instructions: Sequence[dis.Instruction],
        exception_entries: list[dis.ExceptionTableEntry] = None,
    ) -> None:
        """Add edges between basic blocks."""
        pc_to_idx = {instr.offset: i for i, instr in enumerate(instructions)}
        for block in cfg.blocks.values():
            term = block.get_terminator()
            if not term:
                continue
            
            # Standard edges
            if term.opname in self.JUMP_OPS:
                target = term.argval
                if isinstance(target, int):
                    target_block = cfg.get_block_at_pc(target)
                    if target_block:
                        block.add_successor(target_block.id, EdgeKind.JUMP)
                        target_block.predecessors.add(block.id)
            elif term.opname in self.CONDITIONAL_JUMP_OPS:
                target = term.argval
                if isinstance(target, int):
                    target_block = cfg.get_block_at_pc(target)
                    if target_block:
                        if "TRUE" in term.opname or "NOT_NONE" in term.opname:
                            block.add_successor(target_block.id, EdgeKind.BRANCH_TRUE)
                        else:
                            block.add_successor(target_block.id, EdgeKind.BRANCH_FALSE)
                        target_block.predecessors.add(block.id)
                
                # Fallthrough
                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        if "TRUE" in term.opname or "NOT_NONE" in term.opname:
                            block.add_successor(next_block.id, EdgeKind.BRANCH_FALSE)
                        else:
                            block.add_successor(next_block.id, EdgeKind.BRANCH_TRUE)
                        next_block.predecessors.add(block.id)
            elif term.opname in self.LOOP_OPS:
                target = term.argval
                if isinstance(target, int):
                    target_block = cfg.get_block_at_pc(target)
                    if target_block:
                        block.add_successor(target_block.id, EdgeKind.LOOP_EXIT)
                        target_block.predecessors.add(block.id)
                
                # Fallthrough
                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        block.add_successor(next_block.id, EdgeKind.SEQUENTIAL)
                        next_block.predecessors.add(block.id)
            elif term.opname in self.RETURN_OPS | self.RAISE_OPS:
                pass
            # Handle SETUP_FINALLY and friends for older Python
            elif term.opname in {"SETUP_FINALLY", "SETUP_EXCEPT", "SETUP_WITH", "SETUP_ASYNC_WITH"}:
                target = term.argval
                if isinstance(target, int):
                    target_block = cfg.get_block_at_pc(target)
                    if target_block:
                        block.add_successor(target_block.id, EdgeKind.EXCEPTION)
                        target_block.predecessors.add(block.id)
                        target_block.is_exception_handler = True
                
                # Fallthrough
                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        block.add_successor(next_block.id, EdgeKind.SEQUENTIAL)
                        next_block.predecessors.add(block.id)
            else:
                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        block.add_successor(next_block.id, EdgeKind.SEQUENTIAL)
                        next_block.predecessors.add(block.id)
        
        # Add exception edges for Python 3.11+ zero-cost exceptions
        if exception_entries:
            for entry in exception_entries:
                handler_block = cfg.get_block_at_pc(entry.target)
                if not handler_block:
                    continue
                handler_block.is_exception_handler = True
                
                # Any block that overlaps with the try range should have an edge to the handler
                for block in cfg.blocks.values():
                    # Check if any instruction in the block is within the range [entry.start, entry.end)
                    if block.start_pc < entry.end and block.end_pc >= entry.start:
                        # Add edge if not already present
                        if handler_block.id not in block.successors:
                            block.add_successor(handler_block.id, EdgeKind.EXCEPTION)
                            handler_block.predecessors.add(block.id)

    def _compute_dominators(self, cfg: ControlFlowGraph) -> None:
        """Compute dominator sets for all blocks."""
        if not cfg.blocks:
            return
        all_blocks = set(cfg.blocks.keys())
        for block_id in cfg.blocks:
            if block_id == cfg.entry_block_id:
                cfg.dominators[block_id] = {block_id}
            else:
                cfg.dominators[block_id] = set(all_blocks)
        changed = True
        while changed:
            changed = False
            for block in cfg.iter_blocks_forward():
                if block.id == cfg.entry_block_id:
                    continue
                preds = block.predecessors
                if preds:
                    dom_sets: list[set[int]] = [cfg.dominators.get(p, all_blocks) for p in preds]
                    new_dom: set[int] = dom_sets[0].copy()
                    for ds in dom_sets[1:]:
                        new_dom &= ds
                else:
                    new_dom = set()
                new_dom.add(block.id)
                if new_dom != cfg.dominators.get(block.id):
                    cfg.dominators[block.id] = new_dom
                    changed = True
        for block_id, dom_set in cfg.dominators.items():
            block = cfg.blocks[block_id]
            if block_id == cfg.entry_block_id:
                block.immediate_dominator = None
                continue
            candidates = dom_set - {block_id}
            for d in candidates:
                is_immediate = True
                for other in candidates:
                    if other != d and d in cfg.dominators.get(other, set()):
                        is_immediate = False
                        break
                if is_immediate:
                    block.immediate_dominator = d
                    break

    def _identify_loops(self, cfg: ControlFlowGraph) -> None:
        """Identify natural loops in the CFG."""
        for block in cfg.blocks.values():
            for succ_id in block.successors:
                if cfg.dominates(succ_id, block.id):
                    cfg.loop_back_edges.add((block.id, succ_id))
                    cfg.loop_headers.add(succ_id)
                    block.successor_edges[succ_id] = EdgeKind.LOOP_BACK
                    loop_body = self._find_natural_loop(cfg, succ_id, block.id)
                    cfg.natural_loops[succ_id] = loop_body
        for header_id in cfg.loop_headers:
            block = cfg.blocks.get(header_id)
            if block:
                block.is_loop_header = True

    def _find_natural_loop(
        self,
        cfg: ControlFlowGraph,
        header_id: int,
        back_edge_source: int,
    ) -> set[int]:
        """Find all blocks in a natural loop."""
        loop_body = {header_id, back_edge_source}
        worklist = [back_edge_source]
        while worklist:
            block_id = worklist.pop()
            block = cfg.blocks.get(block_id)
            if not block:
                continue
            for pred_id in block.predecessors:
                if pred_id not in loop_body:
                    loop_body.add(pred_id)
                    worklist.append(pred_id)
        return loop_body
