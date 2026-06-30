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

"""Fork paths when modeled ``__len__`` may return a negative symbolic integer.

CPython raises ``ValueError`` for negative lengths used by some containers; this module
SAT-checks ``length < 0`` against current path constraints and may branch into an error
successor while continuing the nonnegative path when feasible.

Side Effects:
    May return :meth:`OpcodeResult.branch` with an error fork; queries the solver via
    :func:`~pysymex._internal.core.solver.engine.check_sat_result`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.exceptions.policy import runtime_exception
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.feasibility.unknowns import (
    FeasibilityBranch,
    UnknownFeasibilitySpec,
    append_fallback_events,
    unknown_feasibility_events,
)
from pysymex._internal.execution.opcodes.common.control.protocol.fallbacks import (
    UNSUPPORTED_MEMBERSHIP_PROTOCOL,
    UNSUPPORTED_TRUTH_PROTOCOL,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

_MEMBERSHIP_LEN_PROTOCOLS = {
    "__contains___truth_len__",
    "__contains_not___truth_len__",
}
_LENGTH_PROTOCOLS = {"__len__", "__len_value__", *_MEMBERSHIP_LEN_PROTOCOLS}
SYMBOLIC_LENGTH_NEGATIVE_FEASIBILITY_UNKNOWN = "symbolic_length_negative_feasibility_unknown"
_SYMBOLIC_LENGTH_NEGATIVE_FEASIBILITY_SPEC = UnknownFeasibilitySpec(
    label=SYMBOLIC_LENGTH_NEGATIVE_FEASIBILITY_UNKNOWN,
    owner="execution.opcodes.control.returns",
    subject="symbolic length negative/nonnegative",
)


def fork_feasible_negative_symbolic_length(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> tuple[VMState | None, OpcodeResult] | None:
    """Fork a length protocol result into CPython valid and negative-error paths."""
    if frame.protocol_method not in _LENGTH_PROTOCOLS:
        return None
    concrete_length = (
        return_value.value if isinstance(return_value, SymbolicValue) else return_value
    )
    if isinstance(concrete_length, bool):
        return None
    if isinstance(concrete_length, int):
        if concrete_length >= 0:
            return None
        error_state = state.fork().push_call(frame)
        return None, _negative_length_error_result(error_state, ctx, Z3_TRUE)
    if not isinstance(return_value, SymbolicValue):
        return None
    if not z3.is_true(simplify_expr(return_value.is_int)):
        return None
    from pysymex._internal.core.solver.engine.queries import check_sat_result

    negative = return_value.z3_int < Z3_ZERO
    if _is_syntactically_nonnegative_int_expr(return_value.z3_int):
        return None
    nonnegative = z3.Not(negative)
    negative_constraints = [*list(state.path_constraints), negative]
    nonnegative_constraints = [*list(state.path_constraints), nonnegative]
    negative_result = check_sat_result(negative_constraints)
    nonnegative_result = check_sat_result(nonnegative_constraints)
    fallback_events = unknown_feasibility_events(
        state=state,
        spec=_SYMBOLIC_LENGTH_NEGATIVE_FEASIBILITY_SPEC,
        branches=[
            FeasibilityBranch("negative", negative_result),
            FeasibilityBranch("nonnegative", nonnegative_result),
        ],
    )
    negative_sat = negative_result.is_sat or _has_hard_theory_witness(negative_constraints)
    nonnegative_sat = nonnegative_result.is_sat or _has_hard_theory_witness(nonnegative_constraints)
    if not negative_sat or (nonnegative_result.is_unknown and not nonnegative_sat):
        return None

    error_state = state.fork().add_constraint(negative).push_call(frame)
    error_result = append_fallback_events(
        _negative_length_error_result(error_state, ctx, negative),
        fallback_events,
    )
    if nonnegative_result.is_unsat:
        return None, error_result
    return state.add_constraint(nonnegative), error_result


def _negative_length_error_result(
    state: VMState,
    ctx: OpcodeDispatcher,
    condition: z3.BoolRef,
) -> OpcodeResult:
    """Raise or report the negative-length branch through normal exception flow."""
    message = "__len__() should return >= 0"
    state.deferred_detector_issues = []
    state.invalidate_cached_hash()
    issue = Issue(
        kind=IssueKind.VALUE_ERROR,
        message=f"Possible ValueError: {message}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow

    replacement = runtime_exception(
        ValueError,
        message,
        state=state,
        condition=condition,
    )
    state.pending_reraise_exception = replacement
    state.invalidate_cached_hash()
    handler_state = ExceptionFlow.unwind_interprocedural_exception(
        state,
        ctx,
        replacement,
    )
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)
    return OpcodeResult.error(issue)


def _canonicalize_proven_nonnegative_symbolic_length(
    protocol_method: str | None,
    return_value: SymbolicValue,
    state: VMState,
) -> SymbolicValue | None:
    """Complete a symbolic length only when negative CPython results are infeasible."""
    if not z3.is_true(simplify_expr(return_value.is_int)):
        return None
    if _is_syntactically_nonnegative_int_expr(return_value.z3_int):
        if protocol_method == "__len_value__":
            return return_value
        truth = return_value.z3_int != Z3_ZERO
        return SymbolicValue(
            _name=f"{return_value.name}_truth",
            z3_int=z3.If(truth, Z3_ONE, Z3_ZERO),
            is_int=Z3_FALSE,
            z3_bool=truth,
            is_bool=Z3_TRUE,
            affinity_type="bool",
        )
    from pysymex._internal.core.solver.engine.queries import check_sat_result

    negative_result = check_sat_result(
        [*list(state.path_constraints), return_value.z3_int < Z3_ZERO],
    )
    if not negative_result.is_unsat:
        return None
    if protocol_method == "__len_value__":
        return return_value
    truth = return_value.z3_int != Z3_ZERO
    return SymbolicValue(
        _name=f"{return_value.name}_truth",
        z3_int=z3.If(truth, Z3_ONE, Z3_ZERO),
        is_int=Z3_FALSE,
        z3_bool=truth,
        is_bool=Z3_TRUE,
        affinity_type="bool",
    )


def normalize_length(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
) -> tuple[StackValue | None, Issue | None, str | None] | None:
    """Normalize a modeled length return or return ``None`` for other protocols."""
    if frame.protocol_method not in _LENGTH_PROTOCOLS:
        return None
    concrete_length = (
        return_value.value if isinstance(return_value, SymbolicValue) else return_value
    )
    truth_method = frame.protocol_method != "__len_value__"
    if isinstance(concrete_length, bool):
        normalized = concrete_length if truth_method else int(concrete_length)
        return SymbolicValue.from_const(normalized), None, None
    if isinstance(concrete_length, int):
        if concrete_length < 0:
            return (
                return_value,
                Issue(
                    kind=IssueKind.VALUE_ERROR,
                    message="Possible ValueError: __len__() should return >= 0",
                    constraints=list(state.path_constraints),
                    pc=state.pc,
                ),
                None,
            )
        normalized = concrete_length != 0 if truth_method else concrete_length
        return SymbolicValue.from_const(normalized), None, None
    if isinstance(return_value, SymbolicValue) and not z3.is_false(
        simplify_expr(return_value.is_int),
    ):
        normalized_symbolic_length = _canonicalize_proven_nonnegative_symbolic_length(
            frame.protocol_method,
            return_value,
            state,
        )
        if normalized_symbolic_length is not None:
            return normalized_symbolic_length, None, None
        if frame.protocol_method in _MEMBERSHIP_LEN_PROTOCOLS:
            return return_value, None, UNSUPPORTED_MEMBERSHIP_PROTOCOL
        return return_value, None, UNSUPPORTED_TRUTH_PROTOCOL
    return (
        return_value,
        Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Possible TypeError: __len__ result cannot be interpreted as an integer",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
        None,
    )


def _is_syntactically_nonnegative_int_expr(expr: z3.ArithRef) -> bool:
    """Return whether *expr* is nonnegative from exact arithmetic syntax alone."""
    literal = _int_literal(expr)
    if literal is not None:
        return literal >= 0
    try:
        kind = expr.decl().kind()
    except z3.Z3Exception:
        return False
    if kind == z3.Z3_OP_MOD and expr.num_args() == 2:
        divisor = _int_literal(expr.arg(1))
        return divisor is not None and divisor > 0
    if kind == z3.Z3_OP_ADD:
        return all(
            isinstance(child, z3.ArithRef) and _is_syntactically_nonnegative_int_expr(child)
            for child in expr.children()
        )
    return False


def _int_literal(expr: z3.ExprRef) -> int | None:
    """Return an integer literal value, if *expr* is syntactically one."""
    if z3.is_int_value(expr):
        return expr.as_long()
    return None


def _has_hard_theory_witness(constraints: list[z3.BoolRef]) -> bool:
    """Return whether concrete substitution proves a hard-theory branch feasible."""
    from pysymex._internal.analysis.detectors.feasibility import hard_theory_witness_model

    return hard_theory_witness_model(constraints) is not None
