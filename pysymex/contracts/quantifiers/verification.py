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

"""Solver-backed checks for parsed quantified contract clauses.

:class:`~pysymex.contracts.quantifiers.verification.QuantifierVerifier` opens quantifier
bodies with witness constants and issues bounded incremental solver queries. Results
are path-local; ``unknown`` outcomes are inconclusive, not proof of correctness.
"""

from __future__ import annotations

import z3

from pysymex.contracts.quantifiers.types import Quantifier, QuantifierKind
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.models import z3_value_to_python
from pysymex.core.solver.engine.results import SolverResult
from pysymex.logger import get_logger

logger = get_logger(__name__)


class QuantifierVerifier:
    """Check quantified clauses with witness substitution and negation queries."""

    def __init__(self, timeout_ms: int = 5000) -> None:
        """Create a verifier with the given per-query timeout.

        Args:
            timeout_ms: Solver timeout in milliseconds.
        """
        self.timeout_ms = timeout_ms

    @staticmethod
    def _build_evidence_formula(
        quantifier: Quantifier,
        *,
        negate_body: bool,
    ) -> tuple[z3.BoolRef, dict[str, z3.ExprRef]]:
        """Open a quantified body under fresh symbols for extractable evidence.

        Replaces bound variables with fresh constant witness variables and
        applies bounds to construct an open formula.

        Args:
            quantifier: The quantifier structure to open.
            negate_body: Whether to negate the inner body.

        Returns:
            A tuple of:
              - The opened ``z3.BoolRef`` formula with range constraints.
              - A dictionary mapping variable name strings to their fresh Z3
                witness constant terms.

        Raises:
            ValueError: If the number of variables and bounds mismatch, or if a
                quantifier variable lacks a Z3 variable mapping.
        """
        replacements: list[tuple[z3.ExprRef, z3.ExprRef]] = []
        evidence_symbols: dict[str, z3.ExprRef] = {}
        bound_constraints: list[z3.BoolRef] = []
        if len(quantifier.variables) != len(quantifier.bounds):
            raise ValueError("Each quantified variable requires exactly one bound")
        for variable, bound in zip(quantifier.variables, quantifier.bounds, strict=True):
            if variable.z3_var is None:
                raise ValueError(f"Quantified variable has no Z3 expression: {variable.name}")
            witness = z3.FreshConst(variable.sort, f"witness_{variable.name}")
            replacements.append((variable.z3_var, witness))
            evidence_symbols[variable.name] = witness
            bound_constraints.append(bound.to_constraint(witness))
        body = z3.substitute(quantifier.body, *replacements)
        target = z3.Not(body) if negate_body else body
        formula = z3.And(*bound_constraints, target)
        return formula, evidence_symbols

    def _check_formula(
        self,
        formula: z3.BoolRef,
        context_constraints: list[z3.BoolRef] | None,
    ) -> SolverResult:
        """Check an evidence formula under the supplied outer path constraints.

        Args:
            formula: The target formula constraint to check.
            context_constraints: Optional path constraints to assume.

        Returns:
            The ``SolverResult`` from the satisfiability query.
        """
        solver = IncrementalSolver(timeout_ms=self.timeout_ms)
        if context_constraints:
            for constraint in context_constraints:
                solver.add(constraint)
        solver.add(formula)
        return solver.check(need_model=True)

    @staticmethod
    def _extract_evidence(
        model: z3.ModelRef,
        evidence_symbols: dict[str, z3.ExprRef],
    ) -> dict[str, object]:
        """Extract concrete Python values for each quantified witness variable.

        Args:
            model: The Z3 counterexample/witness model.
            evidence_symbols: Map of variable names to witness terms.

        Returns:
            A dictionary of variable names mapped to concrete Python values.
        """
        return {
            name: z3_value_to_python(model.eval(symbol, model_completion=True))
            for name, symbol in evidence_symbols.items()
        }

    def verify_forall(
        self,
        quantifier: Quantifier,
        context_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool | None, dict[str, object] | None]:
        """Verify a universal quantifier clause under path constraints.

        Attempts to find a counterexample by checking if ``not body and range_bounds``
        is satisfiable under context constraints.

        Args:
            quantifier: The universal quantifier to verify.
            context_constraints: Optional active path constraints to assume.

        Returns:
            A tuple of:
              - A boolean: ``True`` if verified (no counterexamples exist),
                ``False`` if violated, or ``None`` on solver timeout/failure.
              - The counterexample dictionary if violated, otherwise ``None``.

        Raises:
            ValueError: If the quantifier is not a ``FORALL`` quantifier.
        """
        if quantifier.kind is not QuantifierKind.FORALL:
            raise ValueError("verify_forall requires a FORALL quantifier")
        formula, evidence_symbols = self._build_evidence_formula(quantifier, negate_body=True)
        try:
            result = self._check_formula(formula, context_constraints)
        except Exception:
            logger.warning("Universal quantifier solver query failed", exc_info=True)
            return None, None
        if result.is_unsat:
            return True, None
        elif result.is_sat and result.model is not None:
            return False, self._extract_evidence(result.model, evidence_symbols)
        else:
            return None, None

    def verify_exists(
        self,
        quantifier: Quantifier,
        context_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool | None, dict[str, object] | None]:
        """Verify an existential quantifier clause under path constraints.

        Checks if the existential clause is satisfiable.

        Args:
            quantifier: The existential quantifier to verify.
            context_constraints: Optional active path constraints to assume.

        Returns:
            A tuple of:
              - A boolean: ``True`` if a witness is found, ``False`` if unsatisfiable,
                or ``None`` on solver timeout/failure.
              - The witness dictionary if satisfiable, otherwise ``None``.

        Raises:
            ValueError: If the quantifier is not an ``EXISTS`` quantifier.
        """
        if quantifier.kind is not QuantifierKind.EXISTS:
            raise ValueError("verify_exists requires an EXISTS quantifier")
        formula, evidence_symbols = self._build_evidence_formula(quantifier, negate_body=False)
        try:
            result = self._check_formula(formula, context_constraints)
        except Exception:
            logger.warning("Existential quantifier solver query failed", exc_info=True)
            return None, None
        if result.is_sat and result.model is not None:
            return True, self._extract_evidence(result.model, evidence_symbols)
        elif result.is_unsat:
            return False, None
        else:
            return None, None


__all__ = ["QuantifierVerifier"]
