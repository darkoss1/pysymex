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

"""Execution-facing path feasibility policy helpers."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import time
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import z3

from pysymex.core.solver.constraints.literals import exact_bool_literal
from pysymex.core.solver.constraints.theory import (
    constraints_include_bitvector_smt_theory,
    constraints_include_complex_smt_theory,
)
from pysymex.analysis.detectors.feasibility import hard_theory_witness_model
from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.feasibility.literals import (
    query_simplifies_to_false_after_literal_substitution,
)
from pysymex.execution.feasibility.telemetry import (
    PathFeasibilityResult,
    PathFeasibilityResultSource,
    emit_path_feasibility_event,
)
from pysymex.core.state.record import VMState, known_sat_prefix_len_for_state
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.execution.session.state import ExecutionSession
    from pysymex.typing import SolverProtocol

__all__ = [
    "check_path_feasibility",
    "known_sat_prefix_len_for_state",
    "record_pending_constraints_checked",
    "should_check_pending_constraints",
    "SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS",
]

HookMap = Mapping[str, Sequence[Callable[..., object]]]

logger = get_logger(__name__)
SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS = "solver_unknown_path_feasibility"
_MIN_HARD_THEORY_PENDING_QUERY_CONSTRAINTS = 12
_MAX_HARD_THEORY_WITNESS_QUERY_CONSTRAINTS = _MIN_HARD_THEORY_PENDING_QUERY_CONSTRAINTS * 2
_SIMPLIFY_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)


@runtime_checkable
class PathExtendingSolver(Protocol):
    """Optional incremental-solver capability for persisting verified path suffixes."""

    def extend_path(self, constraints: Sequence[z3.BoolRef]) -> None:
        """Persist a newly verified path-constraint suffix."""


def should_check_pending_constraints(*, state: VMState, lazy_eval_threshold: int) -> bool:
    """Return whether a path has enough pending constraints to force a solver check."""
    return (
        state.pending_constraint_count > 0
        and state.pending_constraint_count >= lazy_eval_threshold
        and len(state.path_constraints) != state.last_inconclusive_feasibility_len
    )


def check_path_feasibility(
    *,
    session: ExecutionSession,
    solver: SolverProtocol,
    hook_owner: object,
    hooks: HookMap,
    state: VMState,
) -> bool:
    """Return whether the path remains feasible under its full constraint set.

    The solver boundary treats only proven UNSAT as a prune condition. SAT and
    solver-UNKNOWN/timeout behavior continue through ``path_may_be_feasible``'s
    contract, preserving the existing inconclusive-is-not-unsafe policy.
    """
    if state.pending_constraint_count <= 0:
        return True

    start = time.perf_counter()
    session.phase_counts["path_feasibility"] += 1
    pending_constraint_count = state.pending_constraint_count
    path_constraints_count = len(state.path_constraints)
    known_prefix_len = 0
    query_prefix_len = 0
    query_constraints_count = 0
    query_constraints: list[z3.BoolRef] = []
    event_result: PathFeasibilityResult | None = None
    event_source: PathFeasibilityResultSource = "solver_sat"
    solver_called = False
    hard_theory_skipped = False
    try:
        known_prefix_len = known_sat_prefix_len_for_state(state)
        constraints = list(state.path_constraints)
        path_constraints_count = len(constraints)
        query_constraints, query_prefix_len, literal_result = _normalize_pending_suffix(
            constraints,
            known_prefix_len,
        )
        query_constraints_count = len(query_constraints)
        if literal_result is False:
            event_result = "infeasible"
            event_source = "literal_false"
            session.paths_pruned += 1
            _publish_prune_hooks(hook_owner=hook_owner, hooks=hooks, state=state)
            return False
        if literal_result is True:
            event_source = "literal_true"
            result = None
        elif _query_simplifies_to_false(query_constraints):
            event_result = "infeasible"
            event_source = "simplified_false"
            session.paths_pruned += 1
            _publish_prune_hooks(hook_owner=hook_owner, hooks=hooks, state=state)
            return False
        elif _should_skip_hard_theory_pending_query(
            query_constraints,
            constraints_have_bitvector_smt_theory=state.path_constraints.has_bitvector_smt_theory(),
        ):
            if query_simplifies_to_false_after_literal_substitution(query_constraints):
                event_result = "infeasible"
                event_source = "literal_substitution_false"
                session.paths_pruned += 1
                _publish_prune_hooks(hook_owner=hook_owner, hooks=hooks, state=state)
                return False
            if _should_probe_hard_theory_witness(query_constraints) and (
                _query_has_hard_theory_witness(query_constraints)
            ):
                event_source = "hard_theory_witness"
                result = None
            else:
                hard_theory_skipped = True
                event_result = "inconclusive"
                event_source = "hard_theory_skipped"
                _record_solver_unknown_path_feasibility(
                    session=session,
                    state=state,
                    reason=(
                        "skipped hard SMT-theory path feasibility query while checking "
                        f"{state.pending_constraint_count} pending path constraint(s)"
                    ),
                )
                state.last_inconclusive_feasibility_len = len(state.path_constraints)
                return True
        else:
            solver_called = True
            result = solver.check_sat_result(
                query_constraints,
                known_sat_prefix_len=query_prefix_len,
            )
        if result is not None and result.is_unsat:
            event_result = "infeasible"
            event_source = "solver_unsat"
            session.paths_pruned += 1
            _publish_prune_hooks(hook_owner=hook_owner, hooks=hooks, state=state)
            return False
        if result is not None and result.is_unknown:
            event_result = "inconclusive"
            event_source = "solver_unknown"
            _record_solver_unknown_path_feasibility(
                session=session,
                state=state,
                reason=(
                    "solver returned unknown while checking "
                    f"{state.pending_constraint_count} pending path constraint(s)"
                ),
            )
            state.last_inconclusive_feasibility_len = len(state.path_constraints)
            return True

        new_constraints = constraints[known_prefix_len:]
        if isinstance(solver, PathExtendingSolver):
            solver.extend_path(new_constraints)
        else:
            for constraint in new_constraints:
                solver.add(constraint)

        state.pending_constraint_count = 0
        state.last_inconclusive_feasibility_len = -1
        event_result = "feasible"
        return True
    finally:
        elapsed_seconds = time.perf_counter() - start
        session.phase_timers_seconds["path_feasibility"] += elapsed_seconds
        emit_path_feasibility_event(
            session=session,
            state=state,
            pending_constraint_count=pending_constraint_count,
            path_constraints_count=path_constraints_count,
            known_sat_prefix_len=known_prefix_len,
            query_prefix_len=query_prefix_len,
            query_constraints_count=query_constraints_count,
            result=event_result,
            result_source=event_source,
            solver_called=solver_called,
            hard_theory_skipped=hard_theory_skipped,
            policy_latency_ms=elapsed_seconds * 1000.0,
            query_constraints=query_constraints,
        )


def record_pending_constraints_checked(state: VMState) -> None:
    """Record that pending path constraints have been checked by the solver boundary."""
    state.pending_constraint_count = 0


def _normalize_pending_suffix(
    constraints: list[z3.BoolRef],
    known_prefix_len: int,
) -> tuple[list[z3.BoolRef], int, bool | None]:
    """Strip exact Boolean tautologies from pending constraints before SAT checks."""
    prefix = constraints[:known_prefix_len]
    suffix = constraints[known_prefix_len:]
    if not suffix:
        return constraints, known_prefix_len, True

    query_suffix: list[z3.BoolRef] = []
    for constraint in suffix:
        literal = exact_bool_literal(constraint)
        if literal is False:
            return constraints, known_prefix_len, False
        if literal is not True:
            query_suffix.append(constraint)
    if not query_suffix:
        return prefix, len(prefix), True
    return [*prefix, *query_suffix], len(prefix), None


def _query_simplifies_to_false(constraints: Sequence[z3.BoolRef]) -> bool:
    """Return whether cheap formula simplification proves the query is UNSAT."""
    try:
        return z3.is_false(z3.simplify(z3.And(*constraints)))
    except _SIMPLIFY_FAILURES:
        logger.debug("Path feasibility simplification failed; continuing with solver policy")
        return False


def _should_skip_hard_theory_pending_query(
    constraints: Sequence[z3.BoolRef],
    *,
    constraints_have_bitvector_smt_theory: bool | None = None,
) -> bool:
    """Return whether path feasibility should keep a hard query as explicit UNKNOWN."""
    if len(constraints) < _MIN_HARD_THEORY_PENDING_QUERY_CONSTRAINTS:
        return False
    if constraints_have_bitvector_smt_theory is not None:
        if constraints_have_bitvector_smt_theory:
            return True
    elif constraints_include_bitvector_smt_theory(constraints):
        return True
    return constraints_include_complex_smt_theory(constraints)


def _query_has_hard_theory_witness(constraints: list[z3.BoolRef]) -> bool:
    """Return whether bounded substitution proves a hard-theory query SAT."""
    return hard_theory_witness_model(constraints) is not None


def _should_probe_hard_theory_witness(constraints: Sequence[z3.BoolRef]) -> bool:
    """Return whether a bounded hard-theory witness probe is still cheap enough."""
    return len(constraints) <= _MAX_HARD_THEORY_WITNESS_QUERY_CONSTRAINTS


def _record_solver_unknown_path_feasibility(
    *,
    session: ExecutionSession,
    state: VMState,
    reason: str,
) -> None:
    """Record an inconclusive path-feasibility check without pruning the path."""
    session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.UNKNOWN,
            label=SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS,
            owner="execution.feasibility",
            reason=reason,
            pc=state.pc,
            soundness=SoundnessTag.INCONCLUSIVE,
            false_positive_risk=RiskLevel.MEDIUM,
            false_negative_risk=RiskLevel.MEDIUM,
        )
    )


def _publish_prune_hooks(*, hook_owner: object, hooks: HookMap, state: VMState) -> None:
    """Notify prune hooks that path feasibility established UNSAT."""
    for hook in hooks.get("on_prune", ()):
        try:
            hook(hook_owner, state, "infeasible")
        except Exception:
            logger.exception("Plugin hook execution failed")
