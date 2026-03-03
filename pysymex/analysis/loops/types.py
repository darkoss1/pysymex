"""Loop analysis types for pysymex.
Dataclasses, enums, and type-only classes for loop analysis.
"""

from __future__ import annotations


from dataclasses import dataclass, field

from enum import Enum, auto


import z3


class LoopType(Enum):
    """Classification of loop types."""

    FOR_RANGE = auto()

    FOR_ITER = auto()

    WHILE_COND = auto()

    WHILE_TRUE = auto()

    NESTED = auto()

    UNKNOWN = auto()


@dataclass
class LoopBound:
    """Represents loop iteration bounds."""

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
    """Information about a detected loop."""

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
    """An induction variable that changes predictably each iteration."""

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
    """Summary of loop effects for fast-path execution."""

    iterations: z3.ExprRef | int

    variable_effects: dict[str, z3.ExprRef]

    memory_effects: dict[int, dict[str, z3.ExprRef]]

    invariants_verified: bool = False

    can_summarize: bool = False


__all__ = [
    "LoopType",
    "LoopBound",
    "LoopInfo",
    "InductionVariable",
    "LoopSummary",
]
