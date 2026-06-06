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

"""Loop analysis for symbolic execution.

Provides loop detection from bytecode, bound inference via Z3,
induction-variable recognition, invariant generation and proof,
loop summarisation for fast-path execution, and widening operators.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

import z3

from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val


def _empty_induction_vars() -> dict[str, InductionVariable]:
    """Create a typed empty induction-variable mapping."""
    return {}


def _empty_children() -> list[LoopInfo]:
    """Create a typed empty child-loop list."""
    return []


class LoopType(Enum):
    """Classification of loop constructs."""

    FOR_RANGE = auto()
    FOR_ITER = auto()
    WHILE_COND = auto()
    WHILE_TRUE = auto()
    NESTED = auto()
    UNKNOWN = auto()


class LoopInvariantProofStatus(Enum):
    """Outcome of proving a candidate loop invariant."""

    PROVEN = auto()
    DISPROVEN = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class LoopInvariantProof:
    """Structured proof result for a candidate loop invariant."""

    status: LoopInvariantProofStatus
    counterexample: dict[str, object] | None = None
    reason: str | None = None

    @property
    def is_proven(self) -> bool:
        """Return true only when the invariant is definitely proven."""
        return self.status == LoopInvariantProofStatus.PROVEN


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
        """Create a bound with *n* as exact lower, upper, and count."""
        val = get_int_val(n)
        return LoopBound(lower=val, upper=val, exact=val)

    @staticmethod
    def range(low: int, high: int) -> LoopBound:
        """Create a bound spanning [*low*, *high*] iterations."""
        return LoopBound(lower=get_int_val(low), upper=get_int_val(high))

    @staticmethod
    def unbounded() -> LoopBound:
        """Create an unbounded (potentially infinite) loop."""
        return LoopBound(
            lower=Z3_ZERO,
            upper=get_int_val(2**31),
            is_finite=False,
        )

    @staticmethod
    def symbolic(expr: z3.ExprRef) -> LoopBound:
        """Create a bound whose count is the Z3 expression *expr*."""
        return LoopBound(
            lower=Z3_ZERO,
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
    induction_vars: dict[str, InductionVariable] = field(default_factory=_empty_induction_vars)
    invariants: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
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
        """Return the Z3 expression for this variable's value at iteration *i*."""
        return self.initial + self.step * i

    def final_value(self, iterations: z3.ExprRef) -> z3.ExprRef:
        """Return the Z3 expression for the value after *iterations* iterations."""
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
