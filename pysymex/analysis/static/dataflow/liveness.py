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

"""Live-variable data-flow analysis."""

from __future__ import annotations

from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.static.dataflow.bytecode import DELETE_OPS, LOAD_OPS, STORE_OPS
from pysymex.analysis.static.dataflow.framework import DataFlowAnalysis


class LiveVariables(DataFlowAnalysis[frozenset[str]]):
    """
    Live variable analysis (backward).

    A variable is live at a point if it may be used before being redefined.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        """Initialize the LiveVariables analysis with a ControlFlowGraph.

        Args:
            cfg: The control flow graph to perform live-variable analysis on.
        """
        super().__init__(cfg)

    def is_forward(self) -> bool:
        """Indicate whether the analysis is forward or backward.

        Returns:
            False, as live variables analysis is a backward analysis.
        """
        return False

    def initial_value(self) -> frozenset[str]:
        """Return the initial value for the dataflow analysis (empty).

        Returns:
            An empty frozenset representing no live variables initially.
        """
        return frozenset()

    def boundary_value(self) -> frozenset[str]:
        """Return the boundary value at the start/entry of the CFG (empty).

        Returns:
            An empty frozenset representing no live variables at the boundary.
        """
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: frozenset[str],
    ) -> frozenset[str]:
        """Transfer function: (out - kill) union gen."""
        result = set(in_fact)
        for instr in reversed(block.instructions):
            var_name = instr.argval if isinstance(instr.argval, str) else None
            if instr.opname in STORE_OPS | DELETE_OPS and var_name:
                result.discard(var_name)
            if instr.opname in LOAD_OPS and var_name:
                result.add(var_name)
        return frozenset(result)

    def meet(self, facts: list[frozenset[str]]) -> frozenset[str]:
        """Union: variable is live if live on any successor path."""
        if not facts:
            return frozenset()
        result: set[str] = set()
        for fact in facts:
            result |= fact
        return frozenset(result)

    def is_live_at(self, var_name: str, pc: int) -> bool:
        """Check if a variable is live at a specific PC."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return False
        live = set(self.get_out(block.id))
        for instr in reversed(block.instructions):
            if instr.offset < pc:
                break
            var = instr.argval if isinstance(instr.argval, str) else None
            if instr.opname in STORE_OPS | DELETE_OPS and var:
                live.discard(var)
            if instr.opname in LOAD_OPS and var:
                live.add(var)
        return var_name in live


__all__ = ["LiveVariables"]
