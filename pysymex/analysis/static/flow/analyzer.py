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

"""Orchestrate flow-sensitive analysis combining range, None, and type tracking."""

from __future__ import annotations

from types import CodeType

from pysymex.analysis.static.control.cfg import CFGBuilder
from pysymex.analysis.static.dataflow import (
    Definition,
    DefUseAnalysis,
    LiveVariables,
    NullAnalysis,
    ReachingDefinitions,
)


class FlowSensitiveAnalyzer:
    """Combined flow-sensitive analyzer."""

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


__all__ = ["FlowSensitiveAnalyzer"]
