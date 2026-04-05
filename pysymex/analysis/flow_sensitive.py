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

"""
Flow-Sensitive Analysis for pysymex.

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

Implementation split across:
- cfg.py: CFG infrastructure (BasicBlock, ControlFlowGraph, CFGBuilder, EdgeKind)
- dataflow.py: Data flow framework and concrete analyses
- flow_sensitive.py: Orchestration (FlowSensitiveAnalyzer, FlowContext)
"""

from __future__ import annotations

from dataclasses import dataclass
from types import CodeType

import icontract

from .cfg import (
    BasicBlock,
    CFGBuilder,
    ControlFlowGraph,
    EdgeKind,
)
from .dataflow import (
    AvailableExpressions,
    DataFlowAnalysis,
    Definition,
    DefUseAnalysis,
    DefUseChain,
    Expression,
    LiveVariables,
    NullAnalysis,
    NullInfo,
    NullState,
    ReachingDefinitions,
    TypeFlowAnalysis,
    Use,
)

__all__ = [
    "AvailableExpressions",
    "BasicBlock",
    "CFGBuilder",
    "ControlFlowGraph",
    "DataFlowAnalysis",
    "DefUseAnalysis",
    "DefUseChain",
    "Definition",
    "EdgeKind",
    "Expression",
    "FlowContext",
    "FlowSensitiveAnalyzer",
    "LiveVariables",
    "NullAnalysis",
    "NullInfo",
    "NullState",
    "ReachingDefinitions",
    "TypeFlowAnalysis",
    "Use",
]


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

    def __init__(self, code: CodeType) -> None:
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
        for body_blocks in self.cfg.natural_loops.values():
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

    @icontract.require(lambda self, pc: self.cfg.get_block_at_pc(pc) is not None)  # type: ignore[attr-defined]
    def get_dominator(self, pc: int) -> int | None:
        """Get the immediate dominator block for a PC."""
        block = self.cfg.get_block_at_pc(pc)
        if block:
            return block.immediate_dominator
        return None

    @icontract.ensure(lambda result: isinstance(result, bool))
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
    @icontract.require(lambda analyzer, pc: analyzer.cfg.get_block_at_pc(pc) is not None)  # type: ignore[attr-defined]
    @icontract.ensure(lambda result: isinstance(result, FlowContext))
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
