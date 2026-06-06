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

"""Available-expression data-flow analysis."""

from __future__ import annotations

from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.static.dataflow.expression_bytecode import (
    collect_expressions_from_instructions,
    transfer_expressions_for_instructions,
)
from pysymex.analysis.static.dataflow.framework import DataFlowAnalysis
from pysymex.analysis.static.dataflow.types import Expression


class AvailableExpressions(DataFlowAnalysis[frozenset[Expression]]):
    """
    Available expressions analysis.

    An expression is available at a point if it has been computed on all paths
    and its operands have not been redefined.
    """

    def __init__(self, cfg: ControlFlowGraph) -> None:
        """Initialize the AvailableExpressions analysis with a ControlFlowGraph.

        Collects all expressions computed within the control flow graph.

        Args:
            cfg: The control flow graph to perform available expressions analysis on.
        """
        super().__init__(cfg)
        self.all_expressions: set[Expression] = set()
        self._collect_expressions()

    def _collect_expressions(self) -> None:
        """Collect all expressions in the CFG."""
        for block in self.cfg.blocks.values():
            self.all_expressions |= collect_expressions_from_instructions(block.instructions)

    def initial_value(self) -> frozenset[Expression]:
        """Return the initial value for the dataflow analysis (all expressions).

        Returns:
            A frozenset containing all collected expressions in the CFG.
        """
        return frozenset(self.all_expressions)

    def boundary_value(self) -> frozenset[Expression]:
        """Return the boundary value at the start/entry of the CFG (empty).

        Returns:
            An empty frozenset representing no available expressions at the entry point.
        """
        return frozenset()

    def transfer(
        self,
        block: BasicBlock,
        in_fact: frozenset[Expression],
    ) -> frozenset[Expression]:
        """Transfer function: gen union (in - kill)."""
        return transfer_expressions_for_instructions(block.instructions, in_fact)

    def meet(self, facts: list[frozenset[Expression]]) -> frozenset[Expression]:
        """Intersection: expression available only if available on all paths."""
        if not facts:
            return frozenset(self.all_expressions)
        result = set(facts[0])
        for fact in facts[1:]:
            result &= fact
        return frozenset(result)


__all__ = ["AvailableExpressions"]
