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

"""Per-instruction context for flow-sensitive detector passes."""

from __future__ import annotations

from dataclasses import dataclass

from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.static.dataflow import Definition, NullInfo, NullState
from pysymex.analysis.static.flow.analyzer import FlowSensitiveAnalyzer


@dataclass
class FlowContext:
    """Context provided to detectors for flow-sensitive analysis."""

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


__all__ = ["FlowContext"]
