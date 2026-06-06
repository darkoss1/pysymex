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

"""CFG-driven value-range analysis for scanner diagnostics."""

from __future__ import annotations

from collections import defaultdict, deque
import types

from pysymex.analysis.static.control.cfg import CFGBuilder
from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.domains.ranges.branching import RangeBranchingMixin
from pysymex.analysis.domains.ranges.domain import Range
from pysymex.analysis.domains.ranges.state import RangeState
from pysymex.analysis.domains.ranges.transfer import RangeTransferMixin
from pysymex.analysis.domains.ranges.warnings import RangeWarning
from pysymex.logger import get_logger

logger = get_logger(__name__)


class RangeAnalyzer(RangeTransferMixin, RangeBranchingMixin):
    """Performs value range analysis on bytecode."""

    def analyze(
        self,
        code: types.CodeType,
        file_path: str = "<unknown>",
    ) -> tuple[dict[str, Range], list[RangeWarning]]:
        """Analyze function for range information."""
        builder = CFGBuilder()
        cfg = builder.build(code)
        return self._analyze_cfg(cfg, code, file_path)

    def _analyze_cfg(
        self,
        cfg: ControlFlowGraph,
        code: types.CodeType,
        file_path: str,
    ) -> tuple[dict[str, Range], list[RangeWarning]]:
        """Run range analysis on CFG."""
        all_warnings: list[RangeWarning] = []
        states: dict[int, RangeState] = {}
        pc_to_line = self._pc_to_line_map(cfg, code)
        if cfg.entry:
            initial = RangeState()
            for arg in code.co_varnames[: code.co_argcount]:
                initial.set(arg, Range.full())
            states[cfg.entry.block_id] = initial

        worklist: deque[BasicBlock] = deque()
        queued_block_ids: set[int] = set()
        if cfg.entry is not None:
            worklist.append(cfg.entry)
            queued_block_ids.add(cfg.entry.block_id)
        iterations: dict[int, int] = defaultdict(int)
        global_iters = 0
        max_global_iters = len(cfg.blocks) * 10 + 100
        while worklist and global_iters < max_global_iters:
            global_iters += 1
            block = worklist.popleft()
            if not block:
                continue
            queued_block_ids.discard(block.block_id)
            in_state = states.get(block.block_id, RangeState.bottom())
            if in_state.is_bottom:
                continue
            out_state, block_warnings = self._transfer_block(
                block,
                in_state,
                code,
                file_path,
                pc_to_line=pc_to_line,
            )
            all_warnings.extend(block_warnings)
            for succ_id in block.successors:
                old_state = states.get(succ_id, RangeState.bottom())
                edge_kind = block.successor_edges.get(succ_id)
                succ_out_state = self._refine_successor_state(block, out_state, edge_kind)
                if succ_out_state.is_bottom:
                    continue
                iterations[succ_id] += 1
                new_state = (
                    old_state.widen(succ_out_state)
                    if iterations[succ_id] > 3
                    else old_state.join(succ_out_state)
                )
                if not new_state.subset_of(old_state):
                    states[succ_id] = new_state
                    succ_block = cfg.blocks.get(succ_id)
                    if succ_block is not None and succ_id not in queued_block_ids:
                        worklist.append(succ_block)
                        queued_block_ids.add(succ_id)

        if worklist and global_iters >= max_global_iters:
            logger.warning(
                "Range analysis hit iteration limit (%d) - results may be unsound",
                max_global_iters,
            )
        return self._final_ranges(states), all_warnings

    @staticmethod
    def _pc_to_line_map(cfg: ControlFlowGraph, code: types.CodeType) -> dict[int, int]:
        pc_to_line: dict[int, int] = {}
        try:
            last_line = code.co_firstlineno
            line_list = list(code.co_lines())
            if line_list:
                for start, end, line in line_list:
                    if line is not None:
                        last_line = line
                    for pc in range(start, end):
                        pc_to_line[pc] = last_line
            for block in cfg.blocks.values():
                for instr in block.instructions:
                    if instr.offset not in pc_to_line:
                        pc_to_line[instr.offset] = last_line
        except (AttributeError, Exception):
            logger.warning(
                "CFG construction failed during range analysis; continuing without line map",
                exc_info=True,
            )
        return pc_to_line

    @staticmethod
    def _final_ranges(states: dict[int, RangeState]) -> dict[str, Range]:
        final: dict[str, Range] = {}
        for state in states.values():
            for var, range_val in state.variables.items():
                final[var] = final[var].union(range_val) if var in final else range_val
        return final


class ValueRangeChecker:
    """High-level interface for value range checking."""

    def __init__(self) -> None:
        self.analyzer = RangeAnalyzer()

    def check_function(
        self,
        code: types.CodeType,
        file_path: str = "<unknown>",
    ) -> list[RangeWarning]:
        """Check a function for range-related issues."""
        _, warnings = self.analyzer.analyze(code, file_path)
        return warnings

    def check_array_bounds(
        self,
        index_range: Range,
        array_size: int,
    ) -> str | None:
        """Check if index range is within array bounds."""
        if index_range.is_empty:
            return None
        if index_range.low is not None and index_range.low < -array_size:
            return f"Index may be too negative: {index_range}"
        if index_range.high is not None and index_range.high >= array_size:
            return f"Index may be out of bounds: {index_range} (size: {array_size})"
        return None


__all__ = ["RangeAnalyzer", "ValueRangeChecker"]
