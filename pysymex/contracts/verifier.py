# pysymex: Python Symbolic Execution & Formal Verification
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

"""Contract verification engine for pysymex.

Provides :class:`ContractVerifier` which uses Z3 to prove or refute
contract clauses, and :class:`VerificationReport` for aggregating results.

Verification approach:

- **Preconditions**: Check satisfiability — if ``P ∧ path`` is UNSAT the
  function can never be called with valid inputs on this path.
- **Postconditions**: Check validity via Hoare logic — if ``P ∧ path ∧ ¬Q``
  is SAT, a counterexample violating the postcondition exists.
- **Loop invariants**: Inductive verification — base case (holds on entry)
  + inductive step (preserved by body).
- **Assertions**: Standalone validity check against current path constraints.

Note: Full contract verification (including postconditions) is performed
by :class:`VerifiedExecutor` during symbolic execution. This module provides
the low-level Z3 verification utilities used by the executor.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import z3

from pysymex.contracts.compiler import ContractCompiler
from pysymex.contracts.types import (
    Contract,
    ContractViolation,
    VerificationResult,
)

logger = logging.getLogger(__name__)


def _empty_violations() -> list[ContractViolation]:
    """Create a typed empty contract-violation list."""
    return []


class ContractVerifier:
    """Verifies function contracts using Z3 SMT solving.

    Uses Z3 to prove:
      1. Preconditions are satisfiable (function can be called)
      2. Postconditions hold given preconditions (function is correct)
      3. Loop invariants are preserved (inductive proof)
      4. Inline assertions hold on all reachable paths

    Attributes:
        timeout_ms: Solver timeout in milliseconds.
    """

    def __init__(self, timeout_ms: int = 5000) -> None:
        self.timeout_ms: int = timeout_ms
        self._solver: z3.Solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)

    def verify_precondition(
        self,
        contract: Contract,
        path_constraints: list[z3.BoolRef],
        symbols: dict[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify that a precondition can be satisfied.

        Returns ``(VERIFIED, None)`` if satisfiable, ``(UNREACHABLE, None)``
        if the precondition is impossible given path constraints, or
        ``(UNKNOWN, None)`` on solver timeout.
        """
        self._solver.reset()
        for pc in path_constraints:
            self._solver.add(pc)

        pre_expr = ContractCompiler.compile_predicate(contract.predicate, symbols)

        self._solver.push()
        self._solver.add(pre_expr)
        result = self._solver.check()
        self._solver.pop()

        if result == z3.sat:
            return VerificationResult.VERIFIED, None
        elif result == z3.unsat:
            return VerificationResult.UNREACHABLE, None
        else:
            return VerificationResult.UNKNOWN, None

    def verify_postcondition(
        self,
        contract: Contract,
        preconditions: list[Contract],
        path_constraints: list[z3.BoolRef],
        symbols: dict[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify that a postcondition holds given preconditions.

        Uses Hoare logic: ``{P} code {Q}`` is valid if ``P ∧ path ∧ ¬Q``
        is UNSAT (no counterexample exists).
        """
        self._solver.reset()

        for pre in preconditions:
            pre_expr = ContractCompiler.compile_predicate(pre.predicate, symbols)
            self._solver.add(pre_expr)

        for pc in path_constraints:
            self._solver.add(pc)

        post_expr = ContractCompiler.compile_predicate(contract.predicate, symbols)
        self._solver.add(z3.Not(post_expr))

        result = self._solver.check()
        if result == z3.unsat:
            return VerificationResult.VERIFIED, None
        elif result == z3.sat:
            model = self._solver.model()
            counterexample = self._extract_counterexample(model, symbols)
            return VerificationResult.VIOLATED, counterexample
        else:
            return VerificationResult.UNKNOWN, None

    def verify_loop_invariant(
        self,
        inv: Contract,
        loop_condition: z3.BoolRef,
        loop_body_constraints: list[z3.BoolRef],
        pre_loop_constraints: list[z3.BoolRef],
        symbols: dict[str, z3.ExprRef],
        symbols_after: dict[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify a loop invariant using induction.

        1. **Base case**: Invariant holds on loop entry.
        2. **Inductive step**: If invariant holds and loop condition is true,
           invariant still holds after one iteration.
        """
        inv_expr = ContractCompiler.compile_predicate(inv.predicate, symbols)

        self._solver.reset()
        for pc in pre_loop_constraints:
            self._solver.add(pc)
        self._solver.add(z3.Not(inv_expr))
        base_result = self._solver.check()

        if base_result == z3.sat:
            model = self._solver.model()
            return VerificationResult.VIOLATED, self._extract_counterexample(model, symbols)

        self._solver.reset()
        self._solver.add(inv_expr)
        self._solver.add(loop_condition)
        for bc in loop_body_constraints:
            self._solver.add(bc)

        inv_after = ContractCompiler.compile_predicate(inv.predicate, symbols_after)
        self._solver.add(z3.Not(inv_after))

        inductive_result = self._solver.check()
        if inductive_result == z3.sat:
            model = self._solver.model()
            return VerificationResult.VIOLATED, self._extract_counterexample(model, symbols)
        elif inductive_result == z3.unsat and base_result == z3.unsat:
            return VerificationResult.VERIFIED, None
        else:
            return VerificationResult.UNKNOWN, None

    def verify_assertion(
        self,
        condition: z3.BoolRef,
        path_constraints: list[z3.BoolRef],
        symbols: dict[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify an inline assertion."""
        self._solver.reset()
        for pc in path_constraints:
            self._solver.add(pc)
        self._solver.add(z3.Not(condition))

        result = self._solver.check()
        if result == z3.unsat:
            return VerificationResult.VERIFIED, None
        elif result == z3.sat:
            model = self._solver.model()
            counterexample = self._extract_counterexample(model, symbols)
            return VerificationResult.VIOLATED, counterexample
        else:
            return VerificationResult.UNKNOWN, None

    def _extract_counterexample(
        self,
        model: z3.ModelRef,
        symbols: dict[str, z3.ExprRef],
    ) -> dict[str, object]:
        """Extract concrete variable assignments from a Z3 model."""
        counterexample: dict[str, object] = {}
        for name, expr in symbols.items():
            if name.startswith("old_") or name == "__result__":
                continue
            try:
                val = model.eval(expr, model_completion=True)
                if z3.is_int_value(val):
                    counterexample[name] = val.as_long()
                elif z3.is_rational_value(val):
                    counterexample[name] = float(val.as_fraction())
                elif z3.is_true(val):
                    counterexample[name] = True
                elif z3.is_false(val):
                    counterexample[name] = False
                else:
                    counterexample[name] = str(val)
            except z3.Z3Exception:
                logger.debug("Model eval failed for variable %s", name, exc_info=True)
        return counterexample


@dataclass
class VerificationReport:
    """Aggregated verification results for a function."""

    function_name: str
    total_contracts: int = 0
    verified: int = 0
    violated: int = 0
    unknown: int = 0
    violations: list[ContractViolation] = field(default_factory=_empty_violations)

    @property
    def is_verified(self) -> bool:
        """Check if all contracts were verified."""
        return self.violated == 0 and self.unknown == 0

    @property
    def has_violations(self) -> bool:
        """Check if any violations were found."""
        return self.violated > 0

    def add_result(
        self,
        contract: Contract,
        result: VerificationResult,
        counterexample: dict[str, object] | None = None,
        function_name: str | None = None,
    ) -> None:
        """Record a verification result for a single contract."""
        self.total_contracts += 1
        if result == VerificationResult.VERIFIED:
            self.verified += 1
        elif result == VerificationResult.VIOLATED:
            self.violated += 1
            self.violations.append(
                ContractViolation(
                    kind=contract.kind,
                    condition=contract.condition,
                    message=contract.message or contract.condition,
                    line_number=contract.line_number,
                    function_name=function_name,
                    counterexample=counterexample or {},
                )
            )
        else:
            self.unknown += 1

    def format(self) -> str:
        """Format this report for human-readable display."""
        lines = [
            f"Verification Report: {self.function_name}",
            "=" * 50,
            f"Total contracts: {self.total_contracts}",
            f"  Verified: {self.verified}",
            f"  Violated: {self.violated}",
            f"  Unknown:  {self.unknown}",
        ]
        if self.is_verified:
            lines.append("\n✓ All contracts verified!")
        elif self.has_violations:
            lines.append("\n✗ Contract violations found:")
            for v in self.violations:
                lines.append("")
                lines.append(v.format())
        return "\n".join(lines)


__all__ = [
    "ContractVerifier",
    "VerificationReport",
]
