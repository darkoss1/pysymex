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

"""Bytecode CFG and dominator helpers for loop detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import dis

_UNCONDITIONAL_JUMPS = frozenset(
    (
        "JUMP_FORWARD",
        "JUMP_BACKWARD",
        "JUMP_BACKWARD_NO_INTERRUPT",
        "JUMP_ABSOLUTE",
        "JUMP",
        "JUMP_NO_INTERRUPT",
    ),
)
_CONDITIONAL_JUMPS = frozenset(
    (
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
    ),
)
_LOOP_CONDITIONAL_JUMPS = frozenset(("FOR_ITER", "SEND"))
_TERMINAL_OPS = ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS")


def build_cfg(instructions: list[dis.Instruction]) -> dict[int, set[int]]:
    """Build a control-flow graph from bytecode instructions."""
    cfg: dict[int, set[int]] = {}
    for index, instr in enumerate(instructions):
        pc = instr.offset
        cfg.setdefault(pc, set())
        if instr.opname in _UNCONDITIONAL_JUMPS:
            if isinstance(instr.argval, int):
                cfg[pc].add(instr.argval)
        elif instr.opname in _CONDITIONAL_JUMPS | _LOOP_CONDITIONAL_JUMPS:
            if isinstance(instr.argval, int):
                cfg[pc].add(instr.argval)
            if index + 1 < len(instructions):
                cfg[pc].add(instructions[index + 1].offset)
        elif instr.opname not in _TERMINAL_OPS and index + 1 < len(instructions):
            cfg[pc].add(instructions[index + 1].offset)
    return cfg


def reachable_nodes(cfg: dict[int, set[int]], entry: int) -> set[int]:
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


def compute_dominators(
    cfg: dict[int, set[int]],
    entry: int,
) -> dict[int, set[int]]:
    """Compute dominator sets for all CFG nodes."""
    all_nodes = set(cfg.keys())
    for successors in cfg.values():
        all_nodes.update(successors)
    reachable = reachable_nodes(cfg, entry)
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
            new_dom = {node} if not preds else dom[preds[0]].copy()
            for pred in preds[1:]:
                new_dom &= dom[pred]
            new_dom.add(node)
            if new_dom != dom[node]:
                dom[node] = new_dom
                changed = True
    return dom


def find_back_edges(
    cfg: dict[int, set[int]],
    dominators: dict[int, set[int]],
) -> list[tuple[int, int]]:
    """Find CFG edges whose target dominates their source."""
    back_edges: list[tuple[int, int]] = []
    for from_pc, successors in cfg.items():
        for to_pc in successors:
            if to_pc in dominators.get(from_pc, ()):
                back_edges.append((from_pc, to_pc))
    return back_edges
