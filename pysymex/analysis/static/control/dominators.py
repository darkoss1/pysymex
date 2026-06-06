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

"""Dominator computation for control-flow graphs."""

from __future__ import annotations

from pysymex.analysis.static.control.models import ControlFlowGraph


def compute_dominators(cfg: ControlFlowGraph) -> None:
    """Compute forward dominator sets and immediate dominators for all reachable blocks.

    Uses the standard iterative dataflow algorithm:
    ``dom(b) = {b} ∪ ⋂ dom(p)`` for each predecessor *p*, iterated to
    a fixed point.  After convergence, computes the immediate dominator
    for every non-entry block and stores it on ``block.immediate_dominator``.
    """
    if not cfg.blocks:
        return
    all_blocks = set(cfg.blocks.keys())
    for block_id in cfg.blocks:
        if block_id == cfg.entry_block_id:
            cfg.dominators[block_id] = {block_id}
        else:
            cfg.dominators[block_id] = set(all_blocks)
    changed = True
    while changed:
        changed = False
        for block in cfg.iter_blocks_forward():
            if block.id == cfg.entry_block_id:
                continue
            preds = block.predecessors
            if preds:
                dom_sets: list[set[int]] = [cfg.dominators.get(p, all_blocks) for p in preds]
                new_dom: set[int] = dom_sets[0].copy()
                for dom_set in dom_sets[1:]:
                    new_dom &= dom_set
            else:
                new_dom = set()
            new_dom.add(block.id)
            if new_dom != cfg.dominators.get(block.id):
                cfg.dominators[block.id] = new_dom
                changed = True
    for block_id, dom_set in cfg.dominators.items():
        block = cfg.blocks[block_id]
        if block_id == cfg.entry_block_id:
            block.immediate_dominator = None
            continue
        candidates = dom_set - {block_id}
        for dominator_id in sorted(candidates):
            is_immediate = True
            for other in sorted(candidates):
                if other != dominator_id and dominator_id in cfg.dominators.get(other, ()):
                    is_immediate = False
                    break
            if is_immediate:
                block.immediate_dominator = dominator_id
                break
