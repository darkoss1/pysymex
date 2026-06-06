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

"""Emit definite or handler-routed ``TypeError`` for invalid numeric operands.

Detects ``None`` and other CPython-incompatible binary combinations before generic numeric
lowering runs. Jumps to a modeled handler when one exists; otherwise returns a feasible-path
``TYPE_ERROR`` issue.
"""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.analysis.detectors.detector.issue_evidence import (
    constraints_extend_inconclusive_path,
)
from pysymex.analysis.detectors.feasibility import hard_theory_witness_model
from pysymex.core.solver.engine.queries import get_model_result
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.numeric.fallbacks import (
    type_error_feasibility_unknown_event,
)
from pysymex.execution.opcodes.common.numeric.helpers import (
    jump_to_modeled_exception_handler,
)

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


_NON_STRING_OPERATORS = frozenset({"-", "/", "%", "**", "//", "<<", ">>", "&", "|", "^", "@"})
_INCONCLUSIVE_RUNTIME_ERROR_CONFIDENCE = 0.5


def binary_none_type_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    left: object,
    right: object,
    op_symbol: str,
) -> OpcodeResult | None:
    """Report definite CPython TypeError for binary ops involving None."""
    if not _is_none_value(left) and not _is_none_value(right):
        return None
    left_name = _type_name(left)
    right_name = _type_name(right)
    message = f"unsupported operand type(s) for {op_symbol}: '{left_name}' and '{right_name}'"
    handled_state = jump_to_modeled_exception_handler(state, ctx, instr, "TypeError")
    if handled_state is not None:
        return OpcodeResult.continue_with(handled_state)
    return _uncaught_type_error_result(state, message)


def binary_string_type_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    left: object,
    right: object,
    op_symbol: str,
) -> OpcodeResult | None:
    """Report definite CPython TypeError for invalid string binary operands."""
    message = _string_type_error_message(left, right, op_symbol)
    if message is None:
        return None
    handled_state = jump_to_modeled_exception_handler(state, ctx, instr, "TypeError")
    if handled_state is not None:
        return OpcodeResult.continue_with(handled_state)
    return _uncaught_type_error_result(state, message)


def _uncaught_type_error_result(state: VMState, message: str) -> OpcodeResult:
    """Return a terminal TypeError issue only with SAT path/model evidence."""
    constraints = state.path_constraints.to_list()
    witness_model = hard_theory_witness_model(constraints)
    if witness_model is not None:
        return OpcodeResult.error(
            _type_error_issue(
                state=state,
                message=message,
                constraints=constraints,
                model=witness_model,
            )
        )

    if _path_prefix_is_inconclusive(state=state, constraints=constraints):
        return _inconclusive_type_error_result(state=state, message=message)

    model_result = get_model_result(constraints)
    if model_result.is_sat:
        return OpcodeResult.error(
            _type_error_issue(
                state=state,
                message=message,
                constraints=constraints,
                model=model_result.model if model_result.model is not None else {},
            )
        )
    if model_result.is_unsat:
        return OpcodeResult.terminate()

    return _unknown_type_error_result(state=state, message=message)


def _path_prefix_is_inconclusive(*, state: VMState, constraints: list[z3.BoolRef]) -> bool:
    """Return whether constraints extend a path prefix already marked inconclusive."""
    return constraints_extend_inconclusive_path(
        path_constraints=state.path_constraints.to_list(),
        constraints=constraints,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )


def _unknown_type_error_result(*, state: VMState, message: str) -> OpcodeResult:
    """Return an inconclusive terminal TypeError result without definite issue evidence."""
    event = type_error_feasibility_unknown_event(
        state=state,
        reason=f"solver could not establish path feasibility for uncaught TypeError: {message}",
    )
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[event.label],
        terminal=True,
        fallback_events=[event],
    )


def _inconclusive_type_error_result(*, state: VMState, message: str) -> OpcodeResult:
    """Return a low-confidence TypeError issue for a reached but inconclusive path."""
    event = type_error_feasibility_unknown_event(
        state=state,
        reason=(
            f"path feasibility was already inconclusive for a reached uncaught TypeError: {message}"
        ),
    )
    issue = _type_error_issue(
        state=state,
        message=f"path feasibility inconclusive; {message}",
        constraints=state.path_constraints.to_list(),
        model=None,
        confidence=_INCONCLUSIVE_RUNTIME_ERROR_CONFIDENCE,
        likelihood=_INCONCLUSIVE_RUNTIME_ERROR_CONFIDENCE,
    )
    return OpcodeResult.error(
        issue,
        degraded_passes=[event.label],
        fallback_events=[event],
    )


def _type_error_issue(
    *,
    state: VMState,
    message: str,
    constraints: list[z3.BoolRef],
    model: z3.ModelRef | dict[str, object] | None,
    confidence: float = 1.0,
    likelihood: float = 1.0,
) -> Issue:
    """Create a model-backed numeric TypeError issue."""
    return Issue(
        kind=IssueKind.TYPE_ERROR,
        message=f"Possible TypeError: {message}",
        constraints=constraints,
        model=model,
        pc=state.pc,
        confidence=confidence,
        likelihood=likelihood,
    )


def _string_type_error_message(left: object, right: object, op_symbol: str) -> str | None:
    """Return a TypeError message when string operands are definitely invalid."""
    left_is_str = _is_definite_str_value(left)
    right_is_str = _is_definite_str_value(right)
    if not left_is_str and not right_is_str:
        return None

    if op_symbol == "+":
        if left_is_str and _is_definite_non_str_value(right):
            return "Cannot concatenate 'str' with non-'str' operand"
        if right_is_str and _is_definite_non_str_value(left):
            return "Cannot concatenate 'str' with non-'str' operand"
        return None

    if op_symbol == "*":
        if left_is_str and not _is_definite_int_like_value(right):
            return "Can't multiply sequence by non-int operand"
        if right_is_str and not _is_definite_int_like_value(left):
            return "Can't multiply sequence by non-int operand"
        return None

    if op_symbol in _NON_STRING_OPERATORS:
        return f"Unsupported operand type(s) for {op_symbol} involving 'str'"
    return None


def _is_none_value(value: object) -> bool:
    """Return whether *value* is concrete or symbolic ``None``."""
    return value is None or isinstance(value, SymbolicNone)


def _is_definite_str_value(value: object) -> bool:
    """Return whether *value* is definitely a string operand."""
    if isinstance(value, str | SymbolicString):
        return True
    if not isinstance(value, SymbolicValue):
        return False
    if value.affinity_type == "str":
        return True
    return z3.is_true(z3.simplify(value.is_str))


def _is_definite_non_str_value(value: object) -> bool:
    """Return whether *value* is definitely not a string operand."""
    if _is_definite_str_value(value):
        return False
    if not isinstance(value, SymbolicValue):
        return True
    if value.affinity_type in {"bool", "dict", "float", "int", "list", "NoneType"}:
        return True
    return z3.is_false(z3.simplify(value.is_str))


def _is_definite_int_like_value(value: object) -> bool:
    """Return whether *value* is definitely acceptable as a sequence repeat count."""
    if isinstance(value, bool | int):
        return True
    if not isinstance(value, SymbolicValue):
        return False
    if value.affinity_type in {"bool", "int"}:
        return True
    return z3.is_true(z3.simplify(z3.Or(value.is_int, value.is_bool)))


def _type_name(value: object) -> str:
    """Return the CPython type name used in binary ``TypeError`` messages."""
    if isinstance(value, SymbolicNone) or value is None:
        return "NoneType"
    return type(value).__name__
