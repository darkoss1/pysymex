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

"""Offline contract checks via Z3 for analysis and batch verification.

:class:`~pysymex.contracts.verifier.ContractVerifier` compiles clauses with
:class:`~pysymex.contracts.compiler.ContractCompiler` and issues bounded incremental
solver queries. Runtime VM hooks in :mod:`pysymex.contracts.runtime` use the
same encodings but queries the active path solver directly. Does not execute bytecode
or register decorators.
"""

from __future__ import annotations

from pysymex.logger import get_logger
from collections.abc import Mapping

import z3

from pysymex.contracts.binding import is_old_symbol_name
from pysymex.contracts.ir.obligations import QueryKind
from pysymex.contracts.solver import ContractQuery, check_contract_query
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.models import z3_value_to_python
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.contracts.compiler import ContractCompiler
from pysymex.contracts.types import Contract, VerificationResult
from pysymex.contracts.verifier_report import VerificationReport

logger = get_logger(__name__)

__all__ = ["ContractVerifier", "VerificationReport"]


class ContractVerifier:
    """Run precondition, postcondition, loop-invariant, and assertion solver checks.

    Each method returns a :class:`~pysymex.contracts.contract_enums.VerificationResult`
    for the supplied path constraints only. Solver ``unknown`` or exceptions map to
    ``UNKNOWN``; they are not treated as proof of correctness.
    """

    def __init__(self, timeout_ms: int = 5000) -> None:
        """Create a verifier with a dedicated incremental solver instance.

        Args:
            timeout_ms: Per-query solver timeout in milliseconds.
        """
        self.timeout_ms: int = timeout_ms
        self.solver = IncrementalSolver(timeout_ms=timeout_ms)

    def _check_constraints(
        self,
        constraints: list[z3.BoolRef],
        *,
        query_kind: QueryKind,
        need_model: bool = False,
    ) -> SolverResult | None:
        """Run a Z3 satisfiability query.

        Args:
            constraints: List of boolean expressions to check.
            query_kind: Contract query intent for evidence-compatible query metadata.
            need_model: Whether to compute a model if satisfiable.

        Returns:
            The solver result containing SAT/UNSAT/UNKNOWN status, or ``None``
            if query raises an exception.
        """
        query = ContractQuery.from_constraints(
            constraints,
            query_kind=query_kind,
            timeout_ms=self.timeout_ms,
            need_model=need_model,
        )
        token = active_incremental_solver.set(self.solver)
        try:
            return check_contract_query(query)
        except Exception:
            logger.warning("Contract solver query failed", exc_info=True)
            return None
        finally:
            active_incremental_solver.reset(token)

    def verify_precondition(
        self,
        contract: Contract,
        path_constraints: list[z3.BoolRef],
        symbols: Mapping[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify that a precondition is satisfiable under path constraints.

        Checks if ``path_constraints and precondition`` is satisfiable. If not, the
        precondition can never be met on this path.

        Args:
            contract: The precondition clause to verify.
            path_constraints: Active path constraints at the check point.
            symbols: Mapping of variable names to their active Z3 symbolic terms.

        Returns:
            A tuple of:
              - The ``VerificationResult``: ``VERIFIED`` if satisfiable,
                ``UNREACHABLE`` if unsatisfiable, or ``UNKNOWN`` on solver timeout/failure.
              - Always returns ``None`` for the counterexample.
        """
        try:
            pre_expr = ContractCompiler.compile_predicate(contract.predicate, symbols)
        except (TypeError, ValueError, z3.Z3Exception):
            logger.debug("Failed to compile precondition %s", contract.condition, exc_info=True)
            return VerificationResult.UNSUPPORTED, None

        result = self._check_constraints(
            [*path_constraints, pre_expr],
            query_kind=QueryKind.ENTRY_SAT,
        )
        if result is None:
            return VerificationResult.UNKNOWN, None
        if result.is_sat:
            return VerificationResult.VERIFIED, None
        elif result.is_unsat:
            return VerificationResult.UNREACHABLE, None
        else:
            return VerificationResult.UNKNOWN, None

    def verify_postcondition(
        self,
        contract: Contract,
        preconditions: list[Contract],
        path_constraints: list[z3.BoolRef],
        symbols: Mapping[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify that a postcondition holds given preconditions and path constraints.

        Uses Hoare logic: checks if ``preconditions and path_constraints and not postcondition``
        is unsatisfiable. If satisfiable, a counterexample exists.

        Args:
            contract: The postcondition clause to verify.
            preconditions: List of preconditions assumed to hold.
            path_constraints: Active path constraints at return point.
            symbols: Mapping of variable names to their active Z3 symbolic terms.

        Returns:
            A tuple of:
              - The ``VerificationResult``: ``VERIFIED`` if postcondition holds,
                ``VIOLATED`` if a counterexample is found, or ``UNKNOWN``/``UNSUPPORTED``.
              - The counterexample dictionary mapping variable names to concrete
                Python values, or ``None``.
        """
        pre_exprs: list[z3.BoolRef] = []
        for pre in preconditions:
            try:
                pre_expr = ContractCompiler.compile_predicate(pre.predicate, symbols)
            except (TypeError, ValueError, z3.Z3Exception):
                logger.debug("Failed to compile precondition %s", pre.condition, exc_info=True)
                return VerificationResult.UNSUPPORTED, None
            pre_exprs.append(pre_expr)

        try:
            post_expr = ContractCompiler.compile_predicate(contract.predicate, symbols)
        except (TypeError, ValueError, z3.Z3Exception):
            logger.debug("Failed to compile postcondition %s", contract.condition, exc_info=True)
            return VerificationResult.UNSUPPORTED, None
        result = self._check_constraints(
            [*pre_exprs, *path_constraints, z3.Not(post_expr)],
            query_kind=QueryKind.POSTCONDITION,
            need_model=True,
        )
        if result is None:
            return VerificationResult.UNKNOWN, None
        if result.is_unsat:
            return VerificationResult.VERIFIED, None
        elif result.is_sat and result.model is not None:
            model = result.model
            counterexample = self.extract_counterexample(model, symbols)
            return VerificationResult.VIOLATED, counterexample
        else:
            return VerificationResult.UNKNOWN, None

    def verify_loop_invariant(
        self,
        inv: Contract,
        loop_condition: z3.BoolRef,
        loop_body_constraints: list[z3.BoolRef],
        pre_loop_constraints: list[z3.BoolRef],
        symbols: Mapping[str, z3.ExprRef],
        symbols_after: Mapping[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify a loop invariant inductively.

        Asserts:
          1. **Base Case**: The invariant holds upon loop entry.
             (i.e. ``pre_loop_constraints and not invariant`` is UNSAT).
          2. **Inductive Step**: If the invariant holds and loop condition is true,
             the invariant is preserved after one iteration.
             (i.e. ``invariant and loop_condition and loop_body and not invariant_after`` is UNSAT).

        Args:
            inv: The loop invariant clause.
            loop_condition: The loop entrance condition.
            loop_body_constraints: The path constraints accumulated by the loop body.
            pre_loop_constraints: Path constraints active prior to loop entry.
            symbols: Symbol state prior to loop execution.
            symbols_after: Symbol state after one loop iteration.

        Returns:
            A tuple containing the ``VerificationResult`` and an optional counterexample.
        """
        try:
            inv_expr = ContractCompiler.compile_predicate(inv.predicate, symbols)
        except (TypeError, ValueError, z3.Z3Exception):
            logger.debug("Failed to compile loop invariant %s", inv.condition, exc_info=True)
            return VerificationResult.UNSUPPORTED, None

        base_result = self._check_constraints(
            [*pre_loop_constraints, z3.Not(inv_expr)],
            query_kind=QueryKind.LOOP_BASE,
            need_model=True,
        )
        if base_result is None:
            return VerificationResult.UNKNOWN, None

        if base_result.is_sat and base_result.model is not None:
            model = base_result.model
            return VerificationResult.VIOLATED, self.extract_counterexample(model, symbols)

        try:
            inv_after = ContractCompiler.compile_predicate(inv.predicate, symbols_after)
        except (TypeError, ValueError, z3.Z3Exception):
            logger.debug("Failed to compile loop invariant %s", inv.condition, exc_info=True)
            return VerificationResult.UNSUPPORTED, None
        inductive_result = self._check_constraints(
            [inv_expr, loop_condition, *loop_body_constraints, z3.Not(inv_after)],
            query_kind=QueryKind.LOOP_STEP,
            need_model=True,
        )
        if inductive_result is None:
            return VerificationResult.UNKNOWN, None
        if inductive_result.is_sat and inductive_result.model is not None:
            model = inductive_result.model
            return VerificationResult.VIOLATED, self.extract_counterexample(model, symbols)
        elif inductive_result.is_unsat and base_result.is_unsat:
            return VerificationResult.VERIFIED, None
        else:
            return VerificationResult.UNKNOWN, None

    def verify_assertion(
        self,
        condition: z3.BoolRef,
        path_constraints: list[z3.BoolRef],
        symbols: Mapping[str, z3.ExprRef],
    ) -> tuple[VerificationResult, dict[str, object] | None]:
        """Verify that an inline assertion holds.

        Checks if ``path_constraints and not assertion_condition`` is unsatisfiable.

        Args:
            condition: The assertion constraint.
            path_constraints: Active path constraints at assertion point.
            symbols: Mapping of variable names to their active Z3 symbolic terms.

        Returns:
            A tuple containing the ``VerificationResult`` and an optional counterexample.
        """
        result = self._check_constraints(
            [*path_constraints, z3.Not(condition)],
            query_kind=QueryKind.ASSERTION,
            need_model=True,
        )
        if result is None:
            return VerificationResult.UNKNOWN, None
        if result.is_unsat:
            return VerificationResult.VERIFIED, None
        elif result.is_sat and result.model is not None:
            model = result.model
            counterexample = self.extract_counterexample(model, symbols)
            return VerificationResult.VIOLATED, counterexample
        else:
            return VerificationResult.UNKNOWN, None

    def extract_counterexample(
        self,
        model: z3.ModelRef,
        symbols: Mapping[str, z3.ExprRef],
    ) -> dict[str, object]:
        """Extract concrete Python values from a Z3 model.

        Evaluates the symbolic terms defined in ``symbols`` under the solver's
        counterexample model.

        Args:
            model: The Z3 model representing the satisfiable counterexample.
            symbols: Mapping of variable names to Z3 expressions.

        Returns:
            A dictionary mapping variable identifier strings to concrete Python values.
        """
        counterexample: dict[str, object] = {}
        for name, expr in symbols.items():
            if name.startswith("old_") or is_old_symbol_name(name) or name == "__result__":
                continue
            try:
                val = model.eval(expr, model_completion=True)
                counterexample[name] = z3_value_to_python(val)
            except z3.Z3Exception:
                logger.debug("Model eval failed for variable %s", name, exc_info=True)
        return counterexample
