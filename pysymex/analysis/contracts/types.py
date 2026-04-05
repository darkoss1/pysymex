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

"""Contract types and dataclasses for PySyMex contract verification.

Contains the fundamental enums and data structures used throughout
the contract verification system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

import z3


class ContractKind(Enum):
    """Types of contracts."""

    REQUIRES = auto()
    ENSURES = auto()
    INVARIANT = auto()
    LOOP_INVARIANT = auto()
    ASSERT = auto()
    ASSUME = auto()


class VerificationResult(Enum):
    """Result of contract verification."""

    VERIFIED = auto()
    VIOLATED = auto()
    UNKNOWN = auto()
    UNREACHABLE = auto()


@dataclass
class ContractViolation:
    """Represents a contract violation."""

    kind: ContractKind
    condition: str
    message: str
    line_number: int | None = None
    function_name: str | None = None
    counterexample: dict[str, object] = field(default_factory=dict[str, object])

    def format(self) -> str:
        """Format violation for display."""
        location = f" at line {self.line_number}" if self.line_number else ""
        func = f" in {self.function_name}" if self.function_name else ""
        result = f"[{self.kind.name}]{func}{location}: {self.message}\n"
        result += f"  Condition: {self.condition}\n"
        if self.counterexample:
            result += "  Counterexample:\n"
            for var, val in self.counterexample.items():
                result += f"    {var} = {val}\n"
        return result


@dataclass
class Contract:
    """A single contract specification."""

    kind: ContractKind
    condition: str
    z3_expr: z3.BoolRef | None = None
    message: str | None = None
    line_number: int | None = None

    def compile(self, symbols: dict[str, z3.ExprRef]) -> z3.BoolRef:
        """Compile condition string to Z3 expression."""
        from pysymex.analysis.contracts.compiler import ContractCompiler

        expr = ContractCompiler.compile_expression(self.condition, symbols)
        return expr


@dataclass
class FunctionContract:
    """Complete contract specification for a function."""

    function_name: str
    preconditions: list[Contract] = field(default_factory=list[Contract])
    postconditions: list[Contract] = field(default_factory=list[Contract])
    loop_invariants: dict[int, list[Contract]] = field(default_factory=dict[int, list[Contract]])
    old_values: dict[str, str] = field(default_factory=dict[str, str])
    result_var: str = "__result__"

    def add_precondition(
        self, condition: str, message: str | None = None, line: int | None = None
    ) -> None:
        """Add a precondition."""
        self.preconditions.append(
            Contract(
                kind=ContractKind.REQUIRES,
                condition=condition,
                message=message or f"Precondition: {condition}",
                line_number=line,
            )
        )

    def add_postcondition(
        self, condition: str, message: str | None = None, line: int | None = None
    ) -> None:
        """Add a postcondition."""
        self.postconditions.append(
            Contract(
                kind=ContractKind.ENSURES,
                condition=condition,
                message=message or f"Postcondition: {condition}",
                line_number=line,
            )
        )

    def add_loop_invariant(
        self, pc: int, condition: str, message: str | None = None, line: int | None = None
    ) -> None:
        """Add a loop invariant at a specific program counter."""
        if pc not in self.loop_invariants:
            self.loop_invariants[pc] = []
        self.loop_invariants[pc].append(
            Contract(
                kind=ContractKind.LOOP_INVARIANT,
                condition=condition,
                message=message or f"Loop invariant: {condition}",
                line_number=line,
            )
        )


__all__ = [
    "Contract",
    "ContractKind",
    "ContractViolation",
    "FunctionContract",
    "VerificationResult",
]
