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

"""Loop metadata shared by bytecode loop detection and execution scheduling."""

from __future__ import annotations

from dataclasses import dataclass, field


def _empty_children() -> list[LoopInfo]:
    """Create a typed empty child-loop list."""
    return []


@dataclass
class LoopInfo:
    """Information about a detected loop in the bytecode.

    Attributes:
        header_pc: PC of the loop header instruction.
        back_edge_pc: PC of the back-edge jump.
        exit_pcs: PCs of loop-exit targets.
        body_pcs: PCs belonging to the loop body.
        parent: Enclosing outer loop, if nested.
        children: Contained inner loops.
        nesting_depth: Nesting level (0 = outermost).

    """

    header_pc: int
    back_edge_pc: int
    exit_pcs: set[int]
    body_pcs: set[int]
    parent: LoopInfo | None = None
    children: list[LoopInfo] = field(default_factory=_empty_children)
    nesting_depth: int = 0

    def contains_pc(self, pc: int) -> bool:
        """Return ``True`` if *pc* is inside the loop body or is the header."""
        return pc in self.body_pcs or pc == self.header_pc

    def is_header(self, pc: int) -> bool:
        """Return ``True`` if *pc* is the loop header offset."""
        return pc == self.header_pc

    def is_exit(self, pc: int) -> bool:
        """Return ``True`` if *pc* is a loop-exit target."""
        return pc in self.exit_pcs
