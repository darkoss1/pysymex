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

"""Contract injection logic for symbolic execution."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence, Mapping

import z3

from pysymex.contracts.decorators import get_function_contract
from pysymex.core.state import VMState
from pysymex.analysis.detectors import Issue, IssueKind

logger = logging.getLogger(__name__)


def _ensure_z3_expr(val: object) -> z3.ExprRef | None:
    if isinstance(val, z3.ExprRef):
        return val
    if isinstance(val, bool):
        return z3.BoolVal(val)
    if isinstance(val, int):
        return z3.IntVal(val)
    if isinstance(val, float):
        return z3.RealVal(val)
    if isinstance(val, str):
        return z3.StringVal(val)
    for attr in ("z3_int", "z3_bool", "z3_str", "z3_addr"):
        expr = getattr(val, attr, None)
        if isinstance(expr, z3.ExprRef):
            return expr
    return None


def inject_preconditions_initial(state: VMState, func: Callable[..., object]) -> VMState:
    """Inject preconditions into the initial state."""
    contract = get_function_contract(func)
    if not contract or not contract.preconditions:
        return state

    symbols: dict[str, z3.ExprRef] = {}
    for name, stack_val in state.local_vars.items():
        expr = _ensure_z3_expr(stack_val)
        if expr is not None:
            symbols[name] = expr

    for clause in contract.preconditions:
        try:
            cond = clause.compile(symbols)
            state = state.add_constraint(cond)
        except Exception as e:
            logger.warning(f"Failed to compile precondition {clause.condition}: {e}")

    return state


def inject_postconditions(
    state: VMState, func: Callable[..., object], return_value: object, config: object
) -> Issue | None:
    """Check postconditions before returning from a function."""
    contract = get_function_contract(func)
    if not contract or not contract.postconditions:
        return None

    symbols: dict[str, z3.ExprRef] = {}
    for name, stack_val in state.local_vars.items():
        expr = _ensure_z3_expr(stack_val)
        if expr is not None:
            symbols[name] = expr

    ret_expr = _ensure_z3_expr(return_value)
    if ret_expr is not None:
        symbols["return"] = ret_expr
        symbols["__return__"] = ret_expr
        symbols["__result__"] = ret_expr
        symbols["result"] = ret_expr

    for clause in contract.postconditions:
        try:
            cond = clause.compile(symbols)
            from pysymex.core.solver.engine import is_satisfiable

            if is_satisfiable([z3.Not(cond)]):
                return Issue(
                    kind=IssueKind.CONTRACT_VIOLATION,
                    message=f"Postcondition '{clause.condition}' may be violated",
                    line_number=clause.line_number,
                    model=None,
                )
        except Exception as e:
            logger.warning(f"Failed to compile postcondition {clause.condition}: {e}")

    return None


from typing import Any


def inject_call_preconditions(
    state: VMState, func: Callable[..., object], args: Sequence[Any], kwargs: Mapping[str, Any]
) -> Issue | None:
    """Check preconditions when calling a function inter-procedurally."""
    contract = get_function_contract(func)
    if not contract or not contract.preconditions:
        return None

    import inspect

    try:
        sig = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = bound.arguments
    except ValueError:
        return None

    symbols: dict[str, z3.ExprRef] = {}
    for name, stack_val in arguments.items():
        expr = _ensure_z3_expr(stack_val)
        if expr is not None:
            symbols[name] = expr

    for clause in contract.preconditions:
        try:
            cond = clause.compile(symbols)
            from pysymex.core.solver.engine import is_satisfiable, get_model

            constraints = list(state.path_constraints) + [z3.Not(cond)]
            if is_satisfiable(constraints):
                return Issue(
                    kind=IssueKind.CONTRACT_VIOLATION,
                    message=f"Precondition '{clause.condition}' of {getattr(func, '__name__', 'unknown')} may be violated",
                    constraints=constraints,
                    model=get_model(constraints),
                    pc=state.pc,
                    function_name=getattr(func, "__name__", "unknown"),
                )
        except Exception as e:
            logger.warning(f"Failed to compile call precondition {clause.condition}: {e}")

    return None
