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

"""Reaching-definitions and def-use-chain analyses."""

from __future__ import annotations

from collections import defaultdict

from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.static.dataflow.bytecode import (
    DELETE_OPS,
    LOAD_OPS,
    STORE_OPS,
    get_line_number,
)
from pysymex.analysis.static.dataflow.framework import DataFlowAnalysis
from pysymex.analysis.static.dataflow.types import Definition, DefUseChain, Use


class ReachingDefinitions(DataFlowAnalysis[frozenset[Definition]]):
    """
    Reaching definitions analysis.

    For each program point, computes which definitions may reach that point.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        """Initialize the ReachingDefinitions analysis with a ControlFlowGraph.

        Collects all definitions present across all basic blocks in the control flow graph.

        Args:
            cfg: The control flow graph to perform reaching definitions analysis on.
        """
        super().__init__(cfg)
        self.all_defs: set[Definition] = set()
        self.defs_by_var: dict[str, set[Definition]] = defaultdict(set)
        self._collect_definitions()

    def _collect_definitions(self) -> None:
        """Collect all definitions in the CFG."""
        for block in self.cfg.blocks.values():
            for instr in block.instructions:
                if instr.opname in STORE_OPS:
                    var_name = str(instr.argval)
                    defn = Definition(var_name, block.id, instr.offset, get_line_number(instr))
                    self.all_defs.add(defn)
                    self.defs_by_var[var_name].add(defn)

    def initial_value(self) -> frozenset[Definition]:
        """Return the initial value for the dataflow analysis.

        Returns:
            An empty frozenset representing no reaching definitions initially.
        """
        return frozenset()

    def boundary_value(self) -> frozenset[Definition]:
        """Return the boundary value at the start/entry of the CFG.

        Returns:
            An empty frozenset representing no reaching definitions at the entry point.
        """
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: frozenset[Definition],
    ) -> frozenset[Definition]:
        """Transfer function: gen - kill."""
        return self._definitions_after_instructions(block, in_fact, stop_pc=None)

    def meet(self, facts: list[frozenset[Definition]]) -> frozenset[Definition]:
        """Union: a definition reaches if it reaches on any path."""
        if not facts:
            return frozenset()
        result: set[Definition] = set()
        for fact in facts:
            result |= fact
        return frozenset(result)

    def get_reaching_defs_at(self, pc: int) -> frozenset[Definition]:
        """Get definitions reaching a specific PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return frozenset()
        return self._definitions_after_instructions(block, self.get_in(block.id), stop_pc=pc)

    def _definitions_after_instructions(
        self,
        block: BasicBlock,
        in_fact: frozenset[Definition],
        stop_pc: int | None,
    ) -> frozenset[Definition]:
        """Compute the set of reaching definitions after executing instructions in a block.

        Args:
            block: The basic block containing the instructions.
            in_fact: The set of reaching definitions at the start of the simulation.
            stop_pc: Optional program counter offset at which to stop execution.
                If None, simulates the entire block.

        Returns:
            The set of reaching definitions that exist after the simulated instructions.
        """
        result = set(in_fact)
        for instr in block.instructions:
            if stop_pc is not None and instr.offset >= stop_pc:
                break
            if instr.opname in STORE_OPS:
                var_name = str(instr.argval)
                result = {d for d in result if d.var_name != var_name}
                result.add(Definition(var_name, block.id, instr.offset, get_line_number(instr)))
            elif instr.opname in DELETE_OPS:
                var_name = str(instr.argval)
                result = {d for d in result if d.var_name != var_name}
        return frozenset(result)


class DefUseAnalysis:
    """
    Builds def-use chains for a function.

    Combines reaching definitions with use information to create precise data
    flow information.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        """Initialize and run DefUseAnalysis on a ControlFlowGraph.

        Performs reaching definitions analysis and builds def-use chains.

        Args:
            cfg: The control flow graph of the function.
        """
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
                if instr.opname in STORE_OPS:
                    var_name = str(instr.argval)
                    reaching = {d for d in reaching if d.var_name != var_name}
                    reaching.add(
                        Definition(var_name, block.id, instr.offset, get_line_number(instr))
                    )
                elif instr.opname in DELETE_OPS:
                    var_name = str(instr.argval)
                    reaching = {d for d in reaching if d.var_name != var_name}
                if instr.opname in LOAD_OPS:
                    var_name = str(instr.argval)
                    use = Use(var_name, block.id, instr.offset, get_line_number(instr))
                    for defn in reaching:
                        if defn.var_name == var_name and defn in self.chains:
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
        return [defn for defn, chain in self.chains.items() if chain.is_dead()]


__all__ = ["DefUseAnalysis", "ReachingDefinitions"]
