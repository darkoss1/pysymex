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

"""Loop body, exit, and nesting construction helpers."""

from __future__ import annotations

from pysymex._internal.execution.scheduling.loops.types import LoopInfo


def build_loop_info(
    cfg: dict[int, set[int]],
    back_edge_pc: int,
    header_pc: int,
) -> LoopInfo:
    """Build loop metadata from one back edge."""
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
        header_pc=header_pc,
        back_edge_pc=back_edge_pc,
        exit_pcs=exit_pcs,
        body_pcs=body_pcs,
    )


def compute_nesting(loops: list[LoopInfo]) -> None:
    """Mutate loop records with parent/child nesting relationships."""
    sorted_loops = sorted(loops, key=lambda loop: len(loop.body_pcs), reverse=True)
    for index, inner in enumerate(sorted_loops):
        for outer in sorted_loops[:index]:
            if inner.header_pc in outer.body_pcs:
                if inner.parent is None or len(outer.body_pcs) < len(inner.parent.body_pcs):
                    if inner.parent is not None:
                        inner.parent.children.remove(inner)
                    inner.parent = outer
                    outer.children.append(inner)
                    inner.nesting_depth = outer.nesting_depth + 1
