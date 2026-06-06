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

import collections
from abc import ABC, abstractmethod
from typing import Generic

from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.static.dataflow.types import T


class DataFlowAnalysis(ABC, Generic[T]):
    """Abstract worklist-based dataflow analysis over a CFG.

    Supports forward and backward analysis with a configurable lattice.
    Subclasses supply the lattice elements (``initial_value``,
    ``boundary_value``), the ``transfer`` function, and the ``meet``
    operator.  The framework iterates to a fixed point.

    Attributes:
        cfg: The control-flow graph being analysed.
        in_facts: Per-block input lattice values after convergence.
        out_facts: Per-block output lattice values after convergence.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        """Initialize the DataFlowAnalysis with a ControlFlowGraph.

        Args:
            cfg: The control flow graph to be analyzed.
        """
        self.cfg = cfg
        self.in_facts: dict[int, T] = {}
        self.out_facts: dict[int, T] = {}

    @abstractmethod
    def initial_value(self) -> T:
        """Return the lattice bottom (or top) used to initialise non-boundary blocks."""

    @abstractmethod
    def boundary_value(self) -> T:
        """Return the lattice value for the entry block (forward) or exit blocks (backward)."""

    @abstractmethod
    def transfer(self, block: BasicBlock, in_fact: T) -> T:
        """Compute the output fact for *block* given *in_fact*."""

    @abstractmethod
    def meet(self, facts: list[T]) -> T:
        """Combine lattice values from multiple predecessor (or successor) paths."""

    def is_forward(self) -> bool:
        """Return True for forward analysis, False for backward."""
        return True

    def analyze(self) -> None:
        """Run the worklist algorithm to a fixed point.

        Populates :attr:`in_facts` and :attr:`out_facts` for every block.
        Terminates when no block's output (forward) or input (backward)
        changes between iterations.
        """
        if not self.cfg.blocks:
            return

        for block_id in self.cfg.blocks:
            if self.is_forward():
                self.in_facts[block_id] = (
                    self.boundary_value()
                    if block_id == self.cfg.entry_block_id
                    else self.initial_value()
                )
                self.out_facts[block_id] = self.initial_value()
            else:
                self.out_facts[block_id] = (
                    self.boundary_value()
                    if block_id in self.cfg.exit_block_ids
                    else self.initial_value()
                )
                self.in_facts[block_id] = self.initial_value()

        worklist = collections.deque(
            self.cfg.iter_blocks_forward() if self.is_forward() else self.cfg.iter_blocks_reverse()
        )
        on_worklist = {block.id for block in worklist}

        while worklist:
            block = worklist.popleft()
            on_worklist.remove(block.id)

            if self.is_forward():
                self._analyze_forward_block(block, worklist, on_worklist)
            else:
                self._analyze_backward_block(block, worklist, on_worklist)

    def _analyze_forward_block(
        self,
        block: BasicBlock,
        worklist: collections.deque[BasicBlock],
        on_worklist: set[int],
    ) -> None:
        """Analyze a single block in a forward data-flow analysis pass.

        Updates the block's in and out facts. If the out fact changes, adds
        the successor blocks to the worklist.

        Args:
            block: The basic block to analyze.
            worklist: The deque worklist of basic blocks to process.
            on_worklist: The set of basic block IDs currently in the worklist.
        """
        if block.id != self.cfg.entry_block_id:
            pred_outs = [self.out_facts.get(p, self.initial_value()) for p in block.predecessors]
            new_in = self.meet(pred_outs) if pred_outs else self.initial_value()
            if new_in != self.in_facts.get(block.id):
                self.in_facts[block.id] = new_in

        new_out = self.transfer(block, self.in_facts.get(block.id, self.initial_value()))
        if new_out == self.out_facts.get(block.id):
            return
        self.out_facts[block.id] = new_out

        for succ_id in block.successors:
            if succ_id not in on_worklist:
                worklist.append(self.cfg.blocks[succ_id])
                on_worklist.add(succ_id)

    def _analyze_backward_block(
        self,
        block: BasicBlock,
        worklist: collections.deque[BasicBlock],
        on_worklist: set[int],
    ) -> None:
        """Analyze a single block in a backward data-flow analysis pass.

        Updates the block's in and out facts. If the in fact changes, adds
        the predecessor blocks to the worklist.

        Args:
            block: The basic block to analyze.
            worklist: The deque worklist of basic blocks to process.
            on_worklist: The set of basic block IDs currently in the worklist.
        """
        if block.id not in self.cfg.exit_block_ids:
            succ_ins = [self.in_facts.get(s, self.initial_value()) for s in block.successors]
            new_out = self.meet(succ_ins) if succ_ins else self.initial_value()
            if new_out != self.out_facts.get(block.id):
                self.out_facts[block.id] = new_out

        new_in = self.transfer(block, self.out_facts.get(block.id, self.initial_value()))
        if new_in == self.in_facts.get(block.id):
            return
        self.in_facts[block.id] = new_in

        for pred_id in block.predecessors:
            if pred_id not in on_worklist:
                worklist.append(self.cfg.blocks[pred_id])
                on_worklist.add(pred_id)

    def get_in(self, block_id: int) -> T:
        """Return the converged input fact for *block_id*."""
        return self.in_facts.get(block_id, self.initial_value())

    def get_out(self, block_id: int) -> T:
        """Return the converged output fact for *block_id*."""
        return self.out_facts.get(block_id, self.initial_value())


__all__ = ["DataFlowAnalysis"]
