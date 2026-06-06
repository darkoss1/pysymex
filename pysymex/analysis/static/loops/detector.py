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

"""Detect natural loops in bytecode by identifying back edges and computing loop bodies."""

from __future__ import annotations

import dis

from pysymex.analysis.static.loops.types import LoopInfo

_UNCONDITIONAL_JUMPS = frozenset(
    {
        "JUMP_FORWARD",
        "JUMP_BACKWARD",
        "JUMP_BACKWARD_NO_INTERRUPT",
        "JUMP_ABSOLUTE",
        "JUMP",
        "JUMP_NO_INTERRUPT",
    }
)
_CONDITIONAL_JUMPS = frozenset(
    {
        "POP_JUMP_IF_TRUE",
        "POP_JUMP_IF_FALSE",
        "POP_JUMP_IF_NONE",
        "POP_JUMP_IF_NOT_NONE",
        "POP_JUMP_FORWARD_IF_TRUE",
        "POP_JUMP_FORWARD_IF_FALSE",
        "POP_JUMP_FORWARD_IF_NONE",
        "POP_JUMP_FORWARD_IF_NOT_NONE",
        "POP_JUMP_BACKWARD_IF_TRUE",
        "POP_JUMP_BACKWARD_IF_FALSE",
        "POP_JUMP_BACKWARD_IF_NONE",
        "POP_JUMP_BACKWARD_IF_NOT_NONE",
        "JUMP_IF_TRUE_OR_POP",
        "JUMP_IF_FALSE_OR_POP",
        "JUMP_IF_NOT_EXC_MATCH",
    }
)
_LOOP_CONDITIONAL_JUMPS = frozenset({"FOR_ITER", "SEND"})


class LoopDetector:
    """Detects loops in bytecode via control-flow graph analysis."""

    def __init__(self) -> None:
        self._loops: list[LoopInfo] = []
        self._back_edges: list[tuple[int, int]] = []

    def analyze_cfg(
        self,
        instructions: list[dis.Instruction],
        entry_pc: int = 0,
    ) -> list[LoopInfo]:
        """Analyze control flow graph to detect loops."""
        self._loops = []
        self._back_edges = []
        cfg = self._build_cfg(instructions)
        dominators = self._compute_dominators(cfg, entry_pc)
        self._back_edges = self._find_back_edges(cfg, dominators)
        for from_pc, to_pc in self._back_edges:
            self._loops.append(self._build_loop_info(cfg, from_pc, to_pc))
        self._compute_nesting()
        return self._loops

    @property
    def loops(self) -> list[LoopInfo]:
        """Expose detected loops for tests and formal checks."""
        return self._loops

    def _build_cfg(self, instructions: list[dis.Instruction]) -> dict[int, set[int]]:
        """Build control flow graph from instructions."""
        cfg: dict[int, set[int]] = {}
        for i, instr in enumerate(instructions):
            pc = instr.offset
            cfg.setdefault(pc, set())
            if instr.opname in _UNCONDITIONAL_JUMPS:
                if isinstance(instr.argval, int):
                    cfg[pc].add(instr.argval)
            elif instr.opname in _CONDITIONAL_JUMPS | _LOOP_CONDITIONAL_JUMPS:
                if isinstance(instr.argval, int):
                    cfg[pc].add(instr.argval)
                if i + 1 < len(instructions):
                    cfg[pc].add(instructions[i + 1].offset)
            elif instr.opname not in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"):
                if i + 1 < len(instructions):
                    cfg[pc].add(instructions[i + 1].offset)
        return cfg

    @staticmethod
    def _reachable_nodes(cfg: dict[int, set[int]], entry: int) -> set[int]:
        """Return nodes reachable from the entry PC."""
        if entry not in cfg:
            return set()
        reachable: set[int] = set()
        worklist = [entry]
        while worklist:
            node = worklist.pop()
            if node in reachable:
                continue
            reachable.add(node)
            worklist.extend(succ for succ in cfg.get(node, ()) if succ not in reachable)
        return reachable

    def _compute_dominators(
        self,
        cfg: dict[int, set[int]],
        entry: int,
    ) -> dict[int, set[int]]:
        """Compute dominator sets for all nodes."""
        all_nodes = set(cfg.keys())
        for successors in cfg.values():
            all_nodes.update(successors)
        reachable = self._reachable_nodes(cfg, entry)
        dom: dict[int, set[int]] = {}
        for node in all_nodes:
            if node == entry:
                dom[node] = {entry}
            elif node in reachable:
                dom[node] = set(reachable)
            else:
                dom[node] = {node}
        changed = True
        while changed:
            changed = False
            for node in reachable:
                if node == entry:
                    continue
                preds = [n for n, succs in cfg.items() if n in reachable and node in succs]
                if not preds:
                    new_dom = {node}
                else:
                    new_dom = dom[preds[0]].copy()
                for pred in preds[1:]:
                    new_dom &= dom[pred]
                new_dom.add(node)
                if new_dom != dom[node]:
                    dom[node] = new_dom
                    changed = True
        return dom

    def _find_back_edges(
        self,
        cfg: dict[int, set[int]],
        dominators: dict[int, set[int]],
    ) -> list[tuple[int, int]]:
        """Find back edges in CFG."""
        back_edges: list[tuple[int, int]] = []
        for from_pc, successors in cfg.items():
            for to_pc in successors:
                if to_pc in dominators.get(from_pc, ()):
                    back_edges.append((from_pc, to_pc))
        return back_edges

    def _build_loop_info(
        self,
        cfg: dict[int, set[int]],
        back_edge_pc: int,
        header_pc: int,
    ) -> LoopInfo:
        """Build loop info from back edge."""
        body_pcs = {header_pc, back_edge_pc}
        worklist = [back_edge_pc]
        reverse_cfg: dict[int, set[int]] = {}
        for src, dsts in cfg.items():
            for dst in dsts:
                reverse_cfg.setdefault(dst, set()).add(src)
        while worklist:
            pc = worklist.pop()
            for pred in reverse_cfg.get(pc, ()):
                if pred not in body_pcs and pred != header_pc:
                    body_pcs.add(pred)
                    worklist.append(pred)
        exit_pcs: set[int] = set()
        for pc in body_pcs:
            for succ in cfg.get(pc, ()):
                if succ not in body_pcs and succ != header_pc:
                    exit_pcs.add(succ)
        return LoopInfo(
            header_pc=header_pc, back_edge_pc=back_edge_pc, exit_pcs=exit_pcs, body_pcs=body_pcs
        )

    def _compute_nesting(self) -> None:
        """Compute loop nesting relationships."""
        sorted_loops = sorted(self._loops, key=lambda loop: len(loop.body_pcs), reverse=True)
        for i, inner in enumerate(sorted_loops):
            for outer in sorted_loops[:i]:
                if inner.header_pc in outer.body_pcs:
                    if inner.parent is None or len(outer.body_pcs) < len(inner.parent.body_pcs):
                        if inner.parent is not None:
                            inner.parent.children.remove(inner)
                        inner.parent = outer
                        outer.children.append(inner)
                        inner.nesting_depth = outer.nesting_depth + 1

    def get_loop_at(self, pc: int) -> LoopInfo | None:
        """Get the innermost loop containing a PC."""
        candidates = [loop for loop in self._loops if loop.contains_pc(pc)]
        if not candidates:
            return None
        return max(candidates, key=lambda loop: loop.nesting_depth)


__all__ = ["LoopDetector"]
