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

"""Frame-entry contract obligations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.contracts.binding.snapshots import collect_current_derived_symbols
from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex._internal.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex._internal.contracts.obligations.evidence import (
    build_contract_evidence,
    unsupported_reasons_for_exception,
)
from pysymex._internal.contracts.runtime.capture import RuntimeContractOutcome
from pysymex._internal.contracts.runtime.diagnostics import record_diagnostic_issue
from pysymex._internal.contracts.runtime.frame.entry.diagnostics import (
    dependent_postcondition_diagnostics,
    dominant_postcondition_block,
    merge_unsupported_reasons,
)
from pysymex._internal.contracts.solver.query import ContractQuery, check_contract_query
from pysymex._internal.contracts.value.expressions import expression_for_contract_value
from pysymex._internal.core.state.record import StateConstraints, VMState
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.contracts.types import Contract

logger = get_logger(__name__)


@dataclass(slots=True)
class _EntryContractDiagnostics:
    """Mutable diagnostics accumulated while injecting entry contracts."""

    issues: list[Issue] = field(default_factory=list[Issue])
    postcondition_block: VerificationResult | None = None
    postcondition_block_reasons: tuple[UnsupportedReason, ...] = ()

    def block_postconditions(
        self,
        status: VerificationResult,
        reasons: tuple[UnsupportedReason, ...] = (),
    ) -> None:
        """Record that dependent postconditions should be diagnosed."""
        self.postcondition_block = dominant_postcondition_block(
            self.postcondition_block,
            status,
        )
        self.postcondition_block_reasons = merge_unsupported_reasons(
            self.postcondition_block_reasons,
            reasons,
        )


def _contract_symbols(state: VMState) -> dict[str, z3.ExprRef]:
    """Build the Z3 symbol table visible to frame-entry contract clauses."""
    symbols: dict[str, z3.ExprRef] = {}
    for name, stack_val in state.local_vars.items():
        expr = expression_for_contract_value(stack_val)
        if expr is not None:
            symbols[name] = expr
    symbols.update(collect_current_derived_symbols(dict(state.local_vars.items()), state.memory))
    return symbols


def _record_compile_failure(
    diagnostics: _EntryContractDiagnostics,
    clause: Contract,
    func: Callable[..., object],
    state: VMState,
    exc: TypeError | ValueError | z3.Z3Exception,
    *,
    subject: str,
    query_kind: QueryKind,
) -> None:
    """Record an unsupported diagnostic for a clause that failed to compile."""
    unsupported_reasons = unsupported_reasons_for_exception(exc)
    diagnostics.block_postconditions(VerificationResult.UNSUPPORTED, unsupported_reasons)
    logger.debug("Failed to compile %s %s", subject, clause.condition)
    action = "checked" if subject == "precondition" else "modeled"
    message = f"{subject.title()} '{clause.condition}' could not be {action}: {exc}"
    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.FRAME_ENTRY,
        query_kind=query_kind,
        pc=state.pc,
        status=VerificationResult.UNSUPPORTED,
        solver_status=SolverStatus.UNSUPPORTED,
        message=message,
        query_constraints=list(state.path_constraints),
        unsupported_reasons=unsupported_reasons,
    )
    diagnostics.issues.append(
        record_diagnostic_issue(
            clause,
            func,
            state,
            VerificationResult.UNSUPPORTED,
            message,
            evidence=evidence,
        ),
    )


def _precondition_query(state: VMState, condition: z3.BoolRef) -> ContractQuery:
    """Build the satisfiability query for an entry precondition."""
    return ContractQuery.from_constraints(
        [*state.path_constraints, condition],
        query_kind=QueryKind.ENTRY_SAT,
        known_sat_prefix_len=StateConstraints.known_sat_prefix_len(state),
    )


def _record_precondition_solver_failure(
    diagnostics: _EntryContractDiagnostics,
    clause: Contract,
    func: Callable[..., object],
    state: VMState,
    condition: z3.BoolRef,
    query: ContractQuery,
    exc: Exception,
) -> None:
    """Record a solver error while checking precondition satisfiability."""
    diagnostics.block_postconditions(
        VerificationResult.UNKNOWN,
        (UnsupportedReason.SOLVER_FAILURE,),
    )
    message = f"Precondition '{clause.condition}' satisfiability is inconclusive: {exc}"
    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.FRAME_ENTRY,
        query_kind=QueryKind.ENTRY_SAT,
        pc=state.pc,
        status=VerificationResult.UNKNOWN,
        solver_status=SolverStatus.ERROR,
        message=message,
        formula=condition,
        query_constraints=query.constraints,
        unsupported_reasons=(UnsupportedReason.SOLVER_FAILURE,),
        timeout_ms=query.timeout_ms,
        need_model=query.need_model,
        theory_profile=query.theory_profile,
    )
    diagnostics.issues.append(
        record_diagnostic_issue(
            clause,
            func,
            state,
            VerificationResult.UNKNOWN,
            message,
            evidence=evidence,
        ),
    )


def _record_unsat_precondition(
    diagnostics: _EntryContractDiagnostics,
    clause: Contract,
    func: Callable[..., object],
    state: VMState,
    condition: z3.BoolRef,
    query: ContractQuery,
) -> None:
    """Record that a precondition makes entry unreachable."""
    diagnostics.block_postconditions(VerificationResult.UNREACHABLE)
    message = f"Precondition '{clause.condition}' admits no valid entry state"
    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.FRAME_ENTRY,
        query_kind=QueryKind.ENTRY_SAT,
        pc=state.pc,
        status=VerificationResult.UNREACHABLE,
        solver_status=SolverStatus.UNSAT,
        message=message,
        formula=condition,
        query_constraints=query.constraints,
        timeout_ms=query.timeout_ms,
        need_model=query.need_model,
        theory_profile=query.theory_profile,
    )
    diagnostics.issues.append(
        record_diagnostic_issue(
            clause,
            func,
            state,
            VerificationResult.UNREACHABLE,
            message,
            evidence=evidence,
        ),
    )


def _record_unknown_precondition(
    diagnostics: _EntryContractDiagnostics,
    clause: Contract,
    func: Callable[..., object],
    state: VMState,
    condition: z3.BoolRef,
    query: ContractQuery,
) -> None:
    """Record an inconclusive precondition satisfiability result."""
    diagnostics.block_postconditions(VerificationResult.UNKNOWN)
    message = f"Precondition '{clause.condition}' satisfiability is inconclusive"
    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.FRAME_ENTRY,
        query_kind=QueryKind.ENTRY_SAT,
        pc=state.pc,
        status=VerificationResult.UNKNOWN,
        solver_status=SolverStatus.UNKNOWN,
        message=message,
        formula=condition,
        query_constraints=query.constraints,
        timeout_ms=query.timeout_ms,
        need_model=query.need_model,
        theory_profile=query.theory_profile,
    )
    diagnostics.issues.append(
        record_diagnostic_issue(
            clause,
            func,
            state,
            VerificationResult.UNKNOWN,
            message,
            evidence=evidence,
        ),
    )


def _record_verified_precondition(
    clause: Contract,
    func: Callable[..., object],
    state: VMState,
    condition: z3.BoolRef,
    query: ContractQuery,
) -> None:
    """Record a satisfiable precondition as runtime contract evidence."""
    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.FRAME_ENTRY,
        query_kind=QueryKind.ENTRY_SAT,
        pc=state.pc,
        status=VerificationResult.VERIFIED,
        solver_status=SolverStatus.SAT,
        message=f"Precondition '{clause.condition}' is satisfiable",
        formula=condition,
        query_constraints=query.constraints,
        timeout_ms=query.timeout_ms,
        need_model=query.need_model,
        theory_profile=query.theory_profile,
    )
    RuntimeContractOutcome.record_evidence(clause, func, evidence)


def _check_precondition(
    diagnostics: _EntryContractDiagnostics,
    clause: Contract,
    func: Callable[..., object],
    state: VMState,
    condition: z3.BoolRef,
) -> None:
    """Check one compiled precondition and append diagnostics/evidence."""
    query = _precondition_query(state, condition)
    try:
        result = check_contract_query(query)
    except Exception as exc:
        _record_precondition_solver_failure(diagnostics, clause, func, state, condition, query, exc)
        return

    if result.is_unsat:
        _record_unsat_precondition(diagnostics, clause, func, state, condition, query)
    elif result.is_unknown:
        _record_unknown_precondition(diagnostics, clause, func, state, condition, query)
    else:
        _record_verified_precondition(clause, func, state, condition, query)


def _inject_preconditions(
    state: VMState,
    func: Callable[..., object],
    clauses: list[Contract],
    symbols: dict[str, z3.ExprRef],
    diagnostics: _EntryContractDiagnostics,
) -> VMState:
    """Compile, check, and assume all frame-entry preconditions."""
    for clause in clauses:
        try:
            condition = clause.compile(symbols)
        except (TypeError, ValueError, z3.Z3Exception) as exc:
            _record_compile_failure(
                diagnostics,
                clause,
                func,
                state,
                exc,
                subject="precondition",
                query_kind=QueryKind.ENTRY_SAT,
            )
            continue
        _check_precondition(diagnostics, clause, func, state, condition)
        state = state.add_constraint(condition)
    return state


def _inject_assumptions(
    state: VMState,
    func: Callable[..., object],
    clauses: list[Contract],
    symbols: dict[str, z3.ExprRef],
    diagnostics: _EntryContractDiagnostics,
) -> VMState:
    """Compile and assume all frame-entry assumptions."""
    for clause in clauses:
        try:
            state = state.add_constraint(clause.compile(symbols))
        except (TypeError, ValueError, z3.Z3Exception) as exc:
            _record_compile_failure(
                diagnostics,
                clause,
                func,
                state,
                exc,
                subject="assumption",
                query_kind=QueryKind.ASSUMPTION,
            )
    return state


def _append_dependent_postcondition_diagnostics(
    diagnostics: _EntryContractDiagnostics,
    state: VMState,
    func: Callable[..., object],
    postconditions: list[Contract],
    include_postconditions: bool,
) -> None:
    """Append diagnostics for postconditions blocked by entry-clause failures."""
    if include_postconditions and diagnostics.postcondition_block is not None:
        diagnostics.issues.extend(
            dependent_postcondition_diagnostics(
                state,
                func,
                postconditions,
                diagnostics.postcondition_block,
                diagnostics.postcondition_block_reasons,
            ),
        )


def inject_preconditions_initial(
    state: VMState,
    func: Callable[..., object],
    *,
    include_preconditions: bool = True,
    include_postconditions: bool = True,
) -> tuple[VMState, list[Issue], bool]:
    """Inject function entry requirements and trusted assumptions into the state."""
    contract = ContractRegistry.get(func)
    if not contract:
        return state, [], True

    symbols = _contract_symbols(state)
    diagnostics = _EntryContractDiagnostics()
    if include_preconditions and contract.preconditions:
        state = _inject_preconditions(
            state,
            func,
            contract.preconditions,
            symbols,
            diagnostics,
        )
    if contract.assumptions:
        state = _inject_assumptions(state, func, contract.assumptions, symbols, diagnostics)
    _append_dependent_postcondition_diagnostics(
        diagnostics,
        state,
        func,
        contract.postconditions,
        include_postconditions,
    )
    return state, diagnostics.issues, diagnostics.postcondition_block is None
