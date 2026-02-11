"""
Flow-Sensitive Analysis for PySpectre.
This module provides flow-sensitive analysis capabilities that track
how values and types flow through the program, enabling precise
detection of bugs while avoiding false positives.
Features:
- Control flow graph construction
- Dominator analysis
- Reaching definitions
- Live variable analysis
- Def-use chains
- Available expressions
- Type state tracking through branches
"""

from __future__ import annotations
import dis
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Generic,
    TypeVar,
)
from .type_inference import PyType, TypeAnalyzer, TypeEnvironment, TypeState


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
    instructions: list[dis.Instruction] = field(default_factory=list)
    line_numbers: set[int] = field(default_factory=set)
    predecessors: set[int] = field(default_factory=set)
    successors: set[int] = field(default_factory=set)
    successor_edges: dict[int, EdgeKind] = field(default_factory=dict)
    is_entry: bool = False
    is_exit: bool = False
    is_loop_header: bool = False
    is_exception_handler: bool = False
    entry_state: TypeState | None = None
    exit_state: TypeState | None = None
    immediate_dominator: int | None = None
    dominated_blocks: set[int] = field(default_factory=set)

    def __hash__(self) -> int:
        return hash(self.id)

    def add_instruction(self, instr: dis.Instruction) -> None:
        """Add an instruction to this block."""
        self.instructions.append(instr)
        if instr.starts_line:
            self.line_numbers.add(instr.starts_line)
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
        return f"BasicBlock({self.id}, pc={self.start_pc}-{self.end_pc})"


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

    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    entry_block_id: int = 0
    exit_block_ids: set[int] = field(default_factory=set)
    pc_to_block: dict[int, int] = field(default_factory=dict)
    loop_headers: set[int] = field(default_factory=set)
    loop_back_edges: set[tuple[int, int]] = field(default_factory=set)
    natural_loops: dict[int, set[int]] = field(default_factory=dict)
    dominators: dict[int, set[int]] = field(default_factory=dict)
    post_dominators: dict[int, set[int]] = field(default_factory=dict)

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

    def build(self, code: Any) -> ControlFlowGraph:
        """Build CFG from a code object."""
        instructions = list(dis.get_instructions(code))
        if not instructions:
            return ControlFlowGraph()
        leaders = self._find_leaders(instructions)
        cfg = self._create_blocks(instructions, leaders)
        self._add_edges(cfg, instructions)
        self._compute_dominators(cfg)
        self._identify_loops(cfg)
        return cfg

    def _find_leaders(self, instructions: list[dis.Instruction]) -> set[int]:
        """Find leader instructions that start basic blocks."""
        leaders: set[int] = set()
        if instructions:
            leaders.add(instructions[0].offset)
        for i, instr in enumerate(instructions):
            if instr.opname in self.JUMP_OPS | self.CONDITIONAL_JUMP_OPS | self.LOOP_OPS:
                target = instr.argval
                if isinstance(target, int):
                    leaders.add(target)
                if instr.opname in self.CONDITIONAL_JUMP_OPS | self.LOOP_OPS:
                    if i + 1 < len(instructions):
                        leaders.add(instructions[i + 1].offset)
            if instr.opname in self.JUMP_OPS | self.RETURN_OPS | self.RAISE_OPS:
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].offset)
            if instr.opname in self.EXCEPTION_OPS:
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].offset)
        return leaders

    def _create_blocks(
        self,
        instructions: list[dis.Instruction],
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
        instructions: list[dis.Instruction],
    ) -> None:
        """Add edges between basic blocks."""
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
                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        block.add_successor(next_block.id, EdgeKind.SEQUENTIAL)
                        next_block.predecessors.add(block.id)
            elif term.opname in self.RETURN_OPS | self.RAISE_OPS:
                pass
            else:
                term_idx = pc_to_idx.get(term.offset)
                if term_idx is not None and term_idx + 1 < len(instructions):
                    next_pc = instructions[term_idx + 1].offset
                    next_block = cfg.get_block_at_pc(next_pc)
                    if next_block and next_block.id != block.id:
                        block.add_successor(next_block.id, EdgeKind.SEQUENTIAL)
                        next_block.predecessors.add(block.id)

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
                    new_dom = set.intersection(*[cfg.dominators.get(p, all_blocks) for p in preds])
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


T = TypeVar("T")


class DataFlowAnalysis(ABC, Generic[T]):
    """
    Abstract base class for data flow analyses.
    Provides framework for:
    - Forward/backward analysis
    - Must/may analysis
    - Fixed-point iteration
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        self.cfg = cfg
        self.in_facts: dict[int, T] = {}
        self.out_facts: dict[int, T] = {}

    @abstractmethod
    def initial_value(self) -> T:
        """Return the initial value for analysis."""

    @abstractmethod
    def boundary_value(self) -> T:
        """Return the boundary value (entry/exit)."""

    @abstractmethod
    def transfer(self, block: BasicBlock, in_fact: T) -> T:
        """Transfer function: compute output from input."""

    @abstractmethod
    def meet(self, facts: list[T]) -> T:
        """Meet operation: combine facts from multiple paths."""

    def is_forward(self) -> bool:
        """Return True for forward analysis, False for backward."""
        return True

    def analyze(self) -> None:
        """Run the data flow analysis to fixed point."""
        for block_id in self.cfg.blocks:
            if self.is_forward() and block_id == self.cfg.entry_block_id:
                self.in_facts[block_id] = self.boundary_value()
            elif not self.is_forward() and block_id in self.cfg.exit_block_ids:
                self.out_facts[block_id] = self.boundary_value()
            else:
                if self.is_forward():
                    self.in_facts[block_id] = self.initial_value()
                else:
                    self.out_facts[block_id] = self.initial_value()
        changed = True
        iterations = 0
        max_iterations = len(self.cfg.blocks) * 10
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            blocks = (
                self.cfg.iter_blocks_forward()
                if self.is_forward()
                else self.cfg.iter_blocks_reverse()
            )
            for block in blocks:
                if self.is_forward():
                    if block.id != self.cfg.entry_block_id:
                        pred_outs = [
                            self.out_facts.get(p, self.initial_value()) for p in block.predecessors
                        ]
                        if pred_outs:
                            new_in = self.meet(pred_outs)
                        else:
                            new_in = self.initial_value()
                        if new_in != self.in_facts.get(block.id):
                            self.in_facts[block.id] = new_in
                            changed = True
                    new_out = self.transfer(
                        block, self.in_facts.get(block.id, self.initial_value())
                    )
                    if new_out != self.out_facts.get(block.id):
                        self.out_facts[block.id] = new_out
                        changed = True
                else:
                    if block.id not in self.cfg.exit_block_ids:
                        succ_ins = [
                            self.in_facts.get(s, self.initial_value()) for s in block.successors
                        ]
                        if succ_ins:
                            new_out = self.meet(succ_ins)
                        else:
                            new_out = self.initial_value()
                        if new_out != self.out_facts.get(block.id):
                            self.out_facts[block.id] = new_out
                            changed = True
                    new_in = self.transfer(
                        block, self.out_facts.get(block.id, self.initial_value())
                    )
                    if new_in != self.in_facts.get(block.id):
                        self.in_facts[block.id] = new_in
                        changed = True

    def get_in(self, block_id: int) -> T:
        """Get input facts for a block."""
        return self.in_facts.get(block_id, self.initial_value())

    def get_out(self, block_id: int) -> T:
        """Get output facts for a block."""
        return self.out_facts.get(block_id, self.initial_value())


@dataclass(frozen=True)
class Definition:
    """Represents a variable definition."""

    var_name: str
    block_id: int
    pc: int
    line: int | None = None

    def __repr__(self) -> str:
        return f"Def({self.var_name}@{self.pc})"


class ReachingDefinitions(DataFlowAnalysis[frozenset[Definition]]):
    """
    Reaching definitions analysis.
    For each program point, computes which definitions may reach that point.
    Used for:
    - Building def-use chains
    - Detecting undefined variables
    - Detecting dead stores
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        super().__init__(cfg)
        self.all_defs: set[Definition] = set()
        self.defs_by_var: dict[str, set[Definition]] = defaultdict(set)
        self._collect_definitions()

    def _collect_definitions(self) -> None:
        """Collect all definitions in the CFG."""
        for block in self.cfg.blocks.values():
            for instr in block.instructions:
                if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                    var_name = instr.argval
                    defn = Definition(
                        var_name=var_name,
                        block_id=block.id,
                        pc=instr.offset,
                        line=instr.starts_line,
                    )
                    self.all_defs.add(defn)
                    self.defs_by_var[var_name].add(defn)

    def initial_value(self) -> frozenset[Definition]:
        return frozenset()

    def boundary_value(self) -> frozenset[Definition]:
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: frozenset[Definition],
    ) -> frozenset[Definition]:
        """Transfer function: gen - kill."""
        result = set(in_fact)
        for instr in block.instructions:
            if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                var_name = instr.argval
                to_remove = {d for d in result if d.var_name == var_name}
                result -= to_remove
                defn = Definition(
                    var_name=var_name,
                    block_id=block.id,
                    pc=instr.offset,
                    line=instr.starts_line,
                )
                result.add(defn)
        return frozenset(result)

    def meet(self, facts: list[frozenset[Definition]]) -> frozenset[Definition]:
        """Union: a definition reaches if it reaches on any path."""
        if not facts:
            return frozenset()
        result = set()
        for f in facts:
            result |= f
        return frozenset(result)

    def get_reaching_defs_at(self, pc: int) -> frozenset[Definition]:
        """Get definitions reaching a specific PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return frozenset()
        result = set(self.get_in(block.id))
        for instr in block.instructions:
            if instr.offset >= pc:
                break
            if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                var_name = instr.argval
                to_remove = {d for d in result if d.var_name == var_name}
                result -= to_remove
                defn = Definition(
                    var_name=var_name,
                    block_id=block.id,
                    pc=instr.offset,
                    line=instr.starts_line,
                )
                result.add(defn)
        return frozenset(result)


class LiveVariables(DataFlowAnalysis[frozenset[str]]):
    """
    Live variable analysis (backward).
    A variable is live at a point if it may be used before being redefined.
    Used for:
    - Dead code elimination
    - Register allocation
    - Detecting unused assignments
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        super().__init__(cfg)

    def is_forward(self) -> bool:
        return False

    def initial_value(self) -> frozenset[str]:
        return frozenset()

    def boundary_value(self) -> frozenset[str]:
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        out_fact: frozenset[str],
    ) -> frozenset[str]:
        """Transfer function: (out - kill) ∪ gen."""
        result = set(out_fact)
        for instr in reversed(block.instructions):
            var_name = instr.argval if isinstance(instr.argval, str) else None
            if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                if var_name:
                    result.discard(var_name)
            if instr.opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                if var_name:
                    result.add(var_name)
        return frozenset(result)

    def meet(self, facts: list[frozenset[str]]) -> frozenset[str]:
        """Union: variable is live if live on any successor path."""
        if not facts:
            return frozenset()
        result = set()
        for f in facts:
            result |= f
        return frozenset(result)

    def is_live_at(self, var_name: str, pc: int) -> bool:
        """Check if a variable is live at a specific PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        live = set(self.get_out(block.id))
        for instr in reversed(block.instructions):
            if instr.offset <= pc:
                break
            var = instr.argval if isinstance(instr.argval, str) else None
            if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                if var:
                    live.discard(var)
            if instr.opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                if var:
                    live.add(var)
        return var_name in live


@dataclass
class Use:
    """Represents a variable use."""

    var_name: str
    block_id: int
    pc: int
    line: int | None = None

    def __repr__(self) -> str:
        return f"Use({self.var_name}@{self.pc})"


@dataclass
class DefUseChain:
    """
    Def-use chain linking definitions to their uses.
    Used for:
    - Data flow tracking
    - Taint analysis
    - Dead store detection
    """

    definition: Definition
    uses: set[Use] = field(default_factory=set)

    def add_use(self, use: Use) -> None:
        """Add a use of this definition."""
        self.uses.add(use)

    def is_dead(self) -> bool:
        """Check if this definition has no uses."""
        return len(self.uses) == 0


class DefUseAnalysis:
    """
    Builds def-use chains for a function.
    Combines reaching definitions with use information
    to create precise data flow information.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        self.cfg = cfg
        self.reaching_defs = ReachingDefinitions(cfg)
        self.chains: dict[Definition, DefUseChain] = {}
        self.reaching_defs.analyze()
        self._build_chains()

    def _build_chains(self) -> None:
        """Build def-use chains."""
        for defn in self.reaching_defs.all_defs:
            self.chains[defn] = DefUseChain(definition=defn)
        for block in self.cfg.blocks.values():
            reaching = set(self.reaching_defs.get_in(block.id))
            for instr in block.instructions:
                if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                    var_name = instr.argval
                    to_remove = {d for d in reaching if d.var_name == var_name}
                    reaching -= to_remove
                    defn = Definition(
                        var_name=var_name,
                        block_id=block.id,
                        pc=instr.offset,
                        line=instr.starts_line,
                    )
                    reaching.add(defn)
                if instr.opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                    var_name = instr.argval
                    use = Use(
                        var_name=var_name,
                        block_id=block.id,
                        pc=instr.offset,
                        line=instr.starts_line,
                    )
                    for defn in reaching:
                        if defn.var_name == var_name:
                            if defn in self.chains:
                                self.chains[defn].add_use(use)

    def get_chain(self, definition: Definition) -> DefUseChain | None:
        """Get the def-use chain for a definition."""
        return self.chains.get(definition)

    def get_definitions_for_use(self, use: Use) -> set[Definition]:
        """Get all definitions that may reach a use."""
        reaching = self.reaching_defs.get_reaching_defs_at(use.pc)
        return {d for d in reaching if d.var_name == use.var_name}

    def find_dead_stores(self) -> list[Definition]:
        """Find definitions that are never used."""
        dead = []
        for defn, chain in self.chains.items():
            if chain.is_dead():
                dead.append(defn)
        return dead


@dataclass(frozen=True)
class Expression:
    """Represents an expression."""

    operator: str
    operands: tuple[str, ...]

    def __repr__(self) -> str:
        if len(self.operands) == 1:
            return f"{self.operator}({self.operands[0]})"
        return f"({self.operands[0]} {self.operator} {self.operands[1]})"


class AvailableExpressions(DataFlowAnalysis[frozenset[Expression]]):
    """
    Available expressions analysis.
    An expression is available at a point if it has been computed
    on all paths and its operands haven't been redefined.
    Used for:
    - Common subexpression elimination
    - Optimization
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        super().__init__(cfg)
        self.all_expressions: set[Expression] = set()
        self._collect_expressions()

    def _collect_expressions(self) -> None:
        """Collect all expressions in the CFG."""
        for block in self.cfg.blocks.values():
            stack: list[str] = []
            for instr in block.instructions:
                if instr.opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                    stack.append(str(instr.argval))
                elif instr.opname == "LOAD_CONST":
                    stack.append(f"const_{instr.argval}")
                elif instr.opname == "BINARY_OP":
                    if len(stack) >= 2:
                        right = stack.pop()
                        left = stack.pop()
                        expr = Expression(
                            operator=instr.argrepr,
                            operands=(left, right),
                        )
                        self.all_expressions.add(expr)
                        stack.append(f"({left}{instr.argrepr}{right})")
                elif instr.opname == "UNARY_OP":
                    if stack:
                        operand = stack.pop()
                        expr = Expression(
                            operator=instr.argrepr,
                            operands=(operand,),
                        )
                        self.all_expressions.add(expr)
                        stack.append(f"({instr.argrepr}{operand})")
                elif instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                    if stack:
                        stack.pop()

    def initial_value(self) -> frozenset[Expression]:
        return frozenset(self.all_expressions)

    def boundary_value(self) -> frozenset[Expression]:
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: frozenset[Expression],
    ) -> frozenset[Expression]:
        """Transfer function: gen ∪ (in - kill)."""
        result = set(in_fact)
        stack: list[str] = []
        for instr in block.instructions:
            if instr.opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                stack.append(str(instr.argval))
            elif instr.opname == "LOAD_CONST":
                stack.append(f"const_{instr.argval}")
            elif instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                var_name = str(instr.argval)
                to_remove = {e for e in result if var_name in e.operands}
                result -= to_remove
                if stack:
                    stack.pop()
            elif instr.opname == "BINARY_OP":
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    expr = Expression(
                        operator=instr.argrepr,
                        operands=(left, right),
                    )
                    result.add(expr)
                    stack.append(f"({left}{instr.argrepr}{right})")
        return frozenset(result)

    def meet(self, facts: list[frozenset[Expression]]) -> frozenset[Expression]:
        """Intersection: expression available only if available on all paths."""
        if not facts:
            return frozenset(self.all_expressions)
        result = set(facts[0])
        for f in facts[1:]:
            result &= f
        return frozenset(result)


class TypeFlowAnalysis(DataFlowAnalysis[TypeEnvironment]):
    """
    Flow-sensitive type analysis.
    Tracks types through control flow, handling:
    - Type narrowing from conditions
    - Type widening at merge points
    - Type refinement from isinstance/type guards
    """

    def __init__(
        self,
        cfg: ControlFlowGraph,
        type_analyzer: TypeAnalyzer,
        initial_env: TypeEnvironment | None = None,
    ) -> None:
        super().__init__(cfg)
        self.type_analyzer = type_analyzer
        self.initial_env = initial_env or TypeEnvironment()
        self.branch_conditions: dict[int, tuple[str, PyType, bool]] = {}

    def initial_value(self) -> TypeEnvironment:
        return TypeEnvironment()

    def boundary_value(self) -> TypeEnvironment:
        return self.initial_env.copy()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: TypeEnvironment,
    ) -> TypeEnvironment:
        """Transfer function: update types through the block."""
        env = in_fact.copy()
        for instr in block.instructions:
            self._process_instruction(env, instr)
        return env

    def _process_instruction(
        self,
        env: TypeEnvironment,
        instr: dis.Instruction,
    ) -> None:
        """Process a single instruction for type flow."""
        if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
            var_name = instr.argval
            env.set_type(var_name, PyType.unknown())

    def meet(self, facts: list[TypeEnvironment]) -> TypeEnvironment:
        """Join environments at merge points."""
        if not facts:
            return TypeEnvironment()
        result = facts[0]
        for env in facts[1:]:
            result = result.join(env)
        return result

    def get_type_at(self, pc: int, var_name: str) -> PyType:
        """Get type of a variable at a specific PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return PyType.unknown()
        env = self.get_in(block.id).copy()
        for instr in block.instructions:
            if instr.offset >= pc:
                break
            self._process_instruction(env, instr)
        return env.get_type(var_name)


class NullState(Enum):
    """Possible null states for a variable."""

    DEFINITELY_NULL = auto()
    DEFINITELY_NOT_NULL = auto()
    MAYBE_NULL = auto()
    UNKNOWN = auto()


@dataclass
class NullInfo:
    """Null information for variables."""

    states: dict[str, NullState] = field(default_factory=dict)

    def copy(self) -> NullInfo:
        return NullInfo(states=dict(self.states))

    def get_state(self, var_name: str) -> NullState:
        return self.states.get(var_name, NullState.UNKNOWN)

    def set_state(self, var_name: str, state: NullState) -> None:
        self.states[var_name] = state

    def join(self, other: NullInfo) -> NullInfo:
        """Join two null infos."""
        result = NullInfo()
        all_vars = set(self.states.keys()) | set(other.states.keys())
        for var in all_vars:
            s1 = self.get_state(var)
            s2 = other.get_state(var)
            if s1 == s2:
                result.states[var] = s1
            elif s1 == NullState.UNKNOWN or s2 == NullState.UNKNOWN:
                result.states[var] = NullState.UNKNOWN
            elif s1 == NullState.MAYBE_NULL or s2 == NullState.MAYBE_NULL:
                result.states[var] = NullState.MAYBE_NULL
            elif s1 == NullState.DEFINITELY_NULL and s2 == NullState.DEFINITELY_NOT_NULL:
                result.states[var] = NullState.MAYBE_NULL
            elif s1 == NullState.DEFINITELY_NOT_NULL and s2 == NullState.DEFINITELY_NULL:
                result.states[var] = NullState.MAYBE_NULL
            else:
                result.states[var] = NullState.MAYBE_NULL
        return result

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NullInfo):
            return False
        return self.states == other.states

    def __hash__(self) -> int:
        return hash(tuple(sorted(self.states.items())))


class NullAnalysis(DataFlowAnalysis[NullInfo]):
    """
    Null/None pointer analysis.
    Tracks whether variables can be None at each program point.
    Handles narrowing from None checks.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        super().__init__(cfg)
        self.narrowing_conditions: dict[int, dict[str, NullState]] = {}

    def initial_value(self) -> NullInfo:
        return NullInfo()

    def boundary_value(self) -> NullInfo:
        return NullInfo()

    def transfer(self, block: BasicBlock, in_fact: NullInfo) -> NullInfo:
        """Transfer function for null analysis."""
        info = in_fact.copy()
        for instr in block.instructions:
            if instr.opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
                var_name = instr.argval
                info.set_state(var_name, NullState.MAYBE_NULL)
            if instr.opname == "LOAD_CONST" and instr.argval is None:
                pass
        narrowing = self.narrowing_conditions.get(block.id, {})
        for var_name, state in narrowing.items():
            info.set_state(var_name, state)
        return info

    def meet(self, facts: list[NullInfo]) -> NullInfo:
        """Join null infos."""
        if not facts:
            return NullInfo()
        result = facts[0]
        for info in facts[1:]:
            result = result.join(info)
        return result

    def is_definitely_null(self, var_name: str, pc: int) -> bool:
        """Check if variable is definitely null at PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        info = self.get_in(block.id)
        return info.get_state(var_name) == NullState.DEFINITELY_NULL

    def is_definitely_not_null(self, var_name: str, pc: int) -> bool:
        """Check if variable is definitely not null at PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        info = self.get_in(block.id)
        return info.get_state(var_name) == NullState.DEFINITELY_NOT_NULL

    def may_be_null(self, var_name: str, pc: int) -> bool:
        """Check if variable may be null at PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return True
        info = self.get_in(block.id)
        state = info.get_state(var_name)
        return state in {
            NullState.DEFINITELY_NULL,
            NullState.MAYBE_NULL,
            NullState.UNKNOWN,
        }


class FlowSensitiveAnalyzer:
    """
    Combined flow-sensitive analyzer.
    Integrates multiple analyses:
    - Control flow graph
    - Reaching definitions
    - Live variables
    - Def-use chains
    - Type flow
    - Null analysis
    """

    def __init__(self, code: Any) -> None:
        builder = CFGBuilder()
        self.cfg = builder.build(code)
        self.reaching_defs = ReachingDefinitions(self.cfg)
        self.reaching_defs.analyze()
        self.live_vars = LiveVariables(self.cfg)
        self.live_vars.analyze()
        self.def_use = DefUseAnalysis(self.cfg)
        self.null_analysis = NullAnalysis(self.cfg)
        self.null_analysis.analyze()

    def get_definitions_reaching(self, pc: int, var_name: str) -> set[Definition]:
        """Get definitions of a variable reaching a PC."""
        defs = self.reaching_defs.get_reaching_defs_at(pc)
        return {d for d in defs if d.var_name == var_name}

    def is_variable_live(self, pc: int, var_name: str) -> bool:
        """Check if a variable is live at a PC."""
        return self.live_vars.is_live_at(var_name, pc)

    def is_dead_store(self, definition: Definition) -> bool:
        """Check if a definition is a dead store."""
        chain = self.def_use.get_chain(definition)
        if chain:
            return chain.is_dead()
        return False

    def may_be_null(self, pc: int, var_name: str) -> bool:
        """Check if a variable may be null at a PC."""
        return self.null_analysis.may_be_null(var_name, pc)

    def is_in_loop(self, pc: int) -> bool:
        """Check if a PC is inside a loop."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        for header_id, body_blocks in self.cfg.natural_loops.items():
            if block.id in body_blocks:
                return True
        return False

    def get_loop_header(self, pc: int) -> int | None:
        """Get the loop header for a PC if inside a loop."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return None
        for header_id, body_blocks in self.cfg.natural_loops.items():
            if block.id in body_blocks:
                return header_id
        return None

    def get_dominator(self, pc: int) -> int | None:
        """Get the immediate dominator block for a PC."""
        block = self.cfg.get_block_at_pc(pc)
        if block:
            return block.immediate_dominator
        return None

    def is_reachable(self, pc: int) -> bool:
        """Check if a PC is reachable from entry."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        return self.cfg.is_reachable(block.id)


@dataclass
class FlowContext:
    """
    Context provided to detectors for flow-sensitive analysis.
    """

    cfg: ControlFlowGraph
    analyzer: FlowSensitiveAnalyzer
    pc: int
    block: BasicBlock | None
    reaching_defs: set[Definition]
    live_vars: set[str]
    null_info: NullInfo

    @classmethod
    def create(
        cls,
        analyzer: FlowSensitiveAnalyzer,
        pc: int,
    ) -> FlowContext:
        """Create flow context for a program point."""
        block = analyzer.cfg.get_block_at_pc(pc)
        reaching = analyzer.reaching_defs.get_reaching_defs_at(pc)
        live: set[str] = set()
        if block:
            for var in analyzer.live_vars.get_out(block.id):
                live.add(var)
        null_info = NullInfo()
        if block:
            null_info = analyzer.null_analysis.get_in(block.id)
        return cls(
            cfg=analyzer.cfg,
            analyzer=analyzer,
            pc=pc,
            block=block,
            reaching_defs=set(reaching),
            live_vars=live,
            null_info=null_info,
        )

    def is_variable_defined(self, var_name: str) -> bool:
        """Check if a variable has any reaching definition."""
        return any(d.var_name == var_name for d in self.reaching_defs)

    def is_variable_live(self, var_name: str) -> bool:
        """Check if a variable is live."""
        return var_name in self.live_vars

    def may_be_null(self, var_name: str) -> bool:
        """Check if a variable may be null."""
        return self.null_info.get_state(var_name) in {
            NullState.DEFINITELY_NULL,
            NullState.MAYBE_NULL,
            NullState.UNKNOWN,
        }

    def is_definitely_null(self, var_name: str) -> bool:
        """Check if a variable is definitely null."""
        return self.null_info.get_state(var_name) == NullState.DEFINITELY_NULL

    def is_in_loop(self) -> bool:
        """Check if current location is in a loop."""
        return self.analyzer.is_in_loop(self.pc)
