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

"""Loop analysis types for pysymex.
Dataclasses, enums, and type-only classes for loop analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

import z3


class LoopType(Enum):
    """Classification of loop constructs."""

    FOR_RANGE = auto()
    FOR_ITER = auto()
    WHILE_COND = auto()
    WHILE_TRUE = auto()
    NESTED = auto()
    UNKNOWN = auto()


@dataclass
class LoopBound:
    """Represents loop iteration bounds as Z3 expressions.

    Attributes:
        lower: Lower bound expression.
        upper: Upper bound expression.
        exact: Exact iteration count, if known.
        is_finite: Whether the loop is provably finite.
    """

    lower: z3.ExprRef
    upper: z3.ExprRef
    exact: z3.ExprRef | None = None
    is_finite: bool = True

    @staticmethod
    def constant(n: int) -> LoopBound:
        """Create a constant bound."""
        val = z3.IntVal(n)
        return LoopBound(lower=val, upper=val, exact=val)

    @staticmethod
    def range(low: int, high: int) -> LoopBound:
        """Create a range bound."""
        return LoopBound(lower=z3.IntVal(low), upper=z3.IntVal(high))

    @staticmethod
    def unbounded() -> LoopBound:
        """Create an unbounded (potentially infinite) loop."""
        return LoopBound(
            lower=z3.IntVal(0),
            upper=z3.IntVal(2**31),
            is_finite=False,
        )

    @staticmethod
    def symbolic(expr: z3.ExprRef) -> LoopBound:
        """Create a symbolic bound."""
        return LoopBound(
            lower=z3.IntVal(0),
            upper=expr,
            exact=expr,
        )


@dataclass
class LoopInfo:
    """Information about a detected loop in the bytecode.

    Attributes:
        header_pc: PC of the loop header instruction.
        back_edge_pc: PC of the back-edge jump.
        exit_pcs: PCs of loop-exit targets.
        body_pcs: PCs belonging to the loop body.
        loop_type: Classified loop type.
        bound: Inferred iteration bounds.
        induction_vars: Detected induction variables.
        invariants: Z3 loop invariants.
        parent: Enclosing outer loop, if nested.
        children: Contained inner loops.
        nesting_depth: Nesting level (0 = outermost).
    """

    header_pc: int
    back_edge_pc: int
    exit_pcs: set[int]
    body_pcs: set[int]
    loop_type: LoopType = LoopType.UNKNOWN
    bound: LoopBound | None = None
    induction_vars: dict[str, InductionVariable] = field(default_factory=dict)
    invariants: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    parent: LoopInfo | None = None
    children: list[LoopInfo] = field(default_factory=list)
    nesting_depth: int = 0

    def contains_pc(self, pc: int) -> bool:
        """Check if PC is inside this loop."""
        return pc in self.body_pcs or pc == self.header_pc

    def is_header(self, pc: int) -> bool:
        """Check if PC is the loop header."""
        return pc == self.header_pc

    def is_exit(self, pc: int) -> bool:
        """Check if PC is a loop exit."""
        return pc in self.exit_pcs


@dataclass
class InductionVariable:
    """An induction variable changing predictably each loop iteration.

    Attributes:
        name: Variable name.
        initial: Initial value expression.
        step: Per-iteration increment expression.
        direction: 1 for ascending, -1 for descending.
    """

    name: str
    initial: z3.ExprRef
    step: z3.ExprRef
    direction: int = 1

    def value_at_iteration(self, i: z3.ExprRef) -> z3.ExprRef:
        """Get value at iteration i."""
        return self.initial + self.step * i

    def final_value(self, iterations: z3.ExprRef) -> z3.ExprRef:
        """Get value after all iterations."""
        return self.initial + self.step * iterations


@dataclass
class LoopSummary:
    """Summary of loop effects for fast-path execution.

    Attributes:
        iterations: Number of iterations (symbolic or concrete).
        variable_effects: Final variable values after the loop.
        memory_effects: Final memory-address attribute values.
        invariants_verified: Whether loop invariants were checked.
        can_summarize: Whether the loop can be summarised.
    """

    iterations: z3.ExprRef | int
    variable_effects: dict[str, z3.ExprRef]
    memory_effects: dict[int, dict[str, z3.ExprRef]]
    invariants_verified: bool = False
    can_summarize: bool = False


__all__ = [
    "InductionVariable",
    "LoopBound",
    "LoopInfo",
    "LoopSummary",
    "LoopType",
]
