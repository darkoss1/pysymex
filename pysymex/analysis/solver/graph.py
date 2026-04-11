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
Z3 Engine â€” Graph and state infrastructure.

Provides call graph analysis, control flow graph building,
and symbolic execution state management.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from types import CodeType

from pysymex.analysis.solver.types import BasicBlock, CallSite, SymValue
from pysymex.core.cache import get_instructions as _cached_get_instructions

logger = logging.getLogger(__name__)


class CallGraph:
    """
    Builds and maintains call graph for interprocedural analysis.
    """

    def __init__(self) -> None:
        self.calls: dict[str, set[str]] = defaultdict(set[str])
        self.callers: dict[str, set[str]] = defaultdict(set[str])
        self.call_sites: dict[str, list[CallSite]] = defaultdict(list[CallSite])
        self.entry_points: set[str] = set()
        self.recursive: set[str] = set()

    def add_call(self, site: CallSite) -> None:
        """Add a call relationship."""
        self.calls[site.caller].add(site.callee)
        self.callers[site.callee].add(site.caller)
        self.call_sites[site.caller].append(site)

    def get_callees(self, func: str) -> set[str]:
        """Get all functions called by func."""
        return self.calls.get(func, set())

    def get_callers(self, func: str) -> set[str]:
        """Get all functions that call func."""
        return self.callers.get(func, set())

    def find_recursive(self) -> set[str]:
        """Find all recursive functions (direct or indirect)."""
        recursive: set[str] = set()

        def dfs(start: str, current: str, visited: set[str]) -> None:
            """Dfs."""
            if current in visited:
                if current == start:
                    recursive.add(start)
                return
            visited.add(current)
            for callee in self.calls.get(current, set()):
                dfs(start, callee, visited.copy())

        for func in self.calls:
            dfs(func, func, set())
        self.recursive = recursive
        return recursive

    def topological_order(self) -> list[str]:
        """Get functions in dependency order (leaves first)."""
        in_degree: defaultdict[str, int] = defaultdict(int)
        for callees in self.calls.values():
            for callee in callees:
                in_degree[callee] += 1
        queue: list[str] = [f for f in self.calls if in_degree[f] == 0]
        result: list[str] = []
        while queue:
            func = queue.pop(0)
            result.append(func)
            for callee in self.calls.get(func, set()):
                in_degree[callee] -= 1
                if in_degree[callee] == 0:
                    queue.append(callee)
        return result

    def get_all_affected(self, func: str) -> set[str]:
        """Get all functions that might be affected by changes to func."""
        affected: set[str] = set()
        queue = [func]
        while queue:
            current = queue.pop(0)
            if current in affected:
                continue
            affected.add(current)
            queue.extend(self.callers.get(current, set()))
        return affected


class CFGBuilder:
    """Enhanced control flow graph builder with dominance analysis."""

    BRANCH_OPS = frozenset(
        {
            "JUMP_FORWARD",
            "JUMP_BACKWARD",
            "JUMP_ABSOLUTE",
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
            "FOR_ITER",
            "RETURN_VALUE",
            "RETURN_CONST",
            "RAISE_VARARGS",
            "RERAISE",
            "END_FOR",
        }
    )
    TERMINAL_OPS = frozenset({"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"})

    def build(self, code: CodeType) -> dict[int, BasicBlock]:
        """Build CFG with dominance info."""
        instrs = _cached_get_instructions(code)
        if not instrs:
            return {}
        off_to_idx = {i.offset: idx for idx, i in enumerate(instrs)}
        leaders: set[int] = {0}
        for i, instr in enumerate(instrs):
            if instr.opname in self.BRANCH_OPS:
                if i + 1 < len(instrs):
                    leaders.add(i + 1)
                if instr.argval is not None and instr.argval in off_to_idx:
                    leaders.add(off_to_idx[instr.argval])
        sorted_leaders = sorted(leaders)
        blocks: dict[int, BasicBlock] = {}
        for i, leader in enumerate(sorted_leaders):
            end = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else len(instrs)
            blocks[leader] = BasicBlock(leader, list(instrs[leader:end]))
        self._build_edges(blocks, off_to_idx)
        self._compute_dominators(blocks)
        self._detect_loops(blocks)
        return blocks

    def _build_edges(self, blocks: dict[int, BasicBlock], off_to_idx: dict[int, int]) -> None:
        """Build edges between basic blocks."""
        sorted_ids = sorted(blocks.keys())
        for bid, block in blocks.items():
            if not block.instructions:
                continue
            last = block.instructions[-1]
            op = last.opname
            idx = sorted_ids.index(bid)
            if op in (
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
                "POP_JUMP_FORWARD_IF_FALSE",
                "POP_JUMP_FORWARD_IF_TRUE",
                "POP_JUMP_FORWARD_IF_NONE",
                "POP_JUMP_FORWARD_IF_NOT_NONE",
                "POP_JUMP_BACKWARD_IF_FALSE",
                "POP_JUMP_BACKWARD_IF_TRUE",
                "POP_JUMP_BACKWARD_IF_NONE",
                "POP_JUMP_BACKWARD_IF_NOT_NONE",
                "JUMP_IF_TRUE_OR_POP",
                "JUMP_IF_FALSE_OR_POP",
                "FOR_ITER",
                "SEND",
            ):
                if idx + 1 < len(sorted_ids):
                    succ_id = sorted_ids[idx + 1]
                    block.successors.append((succ_id, "fall"))
                    blocks[succ_id].predecessors.append(bid)
                if last.argval in off_to_idx:
                    target = off_to_idx[last.argval]
                    if target in blocks:
                        block.successors.append((target, "jump"))
                        blocks[target].predecessors.append(bid)
            elif op in ("JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE"):
                if last.argval in off_to_idx:
                    target = off_to_idx[last.argval]
                    if target in blocks:
                        block.successors.append((target, "uncond"))
                        blocks[target].predecessors.append(bid)
            elif op not in self.TERMINAL_OPS:
                if idx + 1 < len(sorted_ids):
                    succ_id = sorted_ids[idx + 1]
                    block.successors.append((succ_id, "uncond"))
                    blocks[succ_id].predecessors.append(bid)

    def _compute_dominators(self, blocks: dict[int, BasicBlock]) -> None:
        """Compute dominator sets for each block."""
        if not blocks:
            return
        all_blocks = set(blocks.keys())
        entry = min(blocks.keys())
        blocks[entry].dominators = {entry}
        for bid in blocks:
            if bid != entry:
                blocks[bid].dominators = all_blocks.copy()
        changed = True
        max_dom_iters = len(blocks) * 3 + 10
        for _dom_iter in range(max_dom_iters):
            if not changed:
                break
            changed = False
            for bid, block in blocks.items():
                if bid == entry:
                    continue
                if block.predecessors:
                    pred_doms: list[set[int]] = [
                        blocks[p].dominators for p in block.predecessors if p in blocks
                    ]
                    new_dom: set[int] = (
                        pred_doms[0].intersection(*pred_doms[1:]) | {bid} if pred_doms else {bid}
                    )
                else:
                    new_dom = {bid}
                if new_dom != block.dominators:
                    block.dominators = new_dom
                    changed = True

    def _detect_loops(self, blocks: dict[int, BasicBlock]) -> None:
        """Detect loop headers using back edges."""
        for block in blocks.values():
            for succ_id, _ in block.successors:
                if succ_id in block.dominators:
                    blocks[succ_id].loop_header = True


class SymbolicState:
    """
    Manages symbolic execution state with rich tracking.
    """

    def __init__(self, parent: SymbolicState | None = None) -> None:
        self.parent = parent
        self.variables: dict[str, SymValue] = {}
        self.stack: list[SymValue] = []
        self.path_constraints: list[object] = []
        self.call_stack: list[str] = []
        self.globals_modified: set[str] = set()
        self._counter = 0
        if parent:
            self.variables = parent.variables.copy()
            self.stack = parent.stack.copy()
            self.path_constraints = parent.path_constraints.copy()
            self.call_stack = parent.call_stack.copy()
            self._counter = parent._counter

    def fork(self) -> SymbolicState:
        """Create a copy for path exploration."""
        return SymbolicState(self)

    def fresh_name(self, prefix: str = "v") -> str:
        """Generate a fresh unique name."""
        self._counter += 1
        return f"{prefix}_{self._counter}"

    _MAX_CONSTRAINTS = 500

    def add_constraint(self, constraint: object) -> None:
        """Add a path constraint."""
        if constraint is not None and len(self.path_constraints) < self._MAX_CONSTRAINTS:
            self.path_constraints.append(constraint)

    def get_var(self, name: str) -> SymValue | None:
        """Get variable by name."""
        return self.variables.get(name)

    def set_var(self, name: str, value: SymValue) -> None:
        """Set variable value."""
        self.variables[name] = value

    def push(self, value: SymValue) -> None:
        """Push value onto stack."""
        self.stack.append(value)

    def pop(self) -> SymValue | None:
        """Pop value from stack."""
        return self.stack.pop() if self.stack else None

    def peek(self, n: int = 1) -> SymValue | None:
        """Peek at stack without popping."""
        if len(self.stack) >= n:
            return self.stack[-n]
        return None

