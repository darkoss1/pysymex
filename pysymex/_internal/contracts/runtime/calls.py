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

"""Evaluate callee preconditions and assumptions at call sites.

Binds call arguments to the callee signature, compiles ``@requires`` clauses, queries
:mod:`pysymex._internal.core.solver` for feasible violations, and adds satisfied preconditions and
``@assumes`` constraints to the caller :class:`~pysymex._internal.core.state.record.VMState`. Returns
``None`` for the state when any clause cannot be compiled. Frame-entry checks live in
:mod:`pysymex._internal.contracts.runtime.entry`.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.contracts.enums import VerificationResult
from pysymex._internal.contracts.runtime.call.conditions import (
    callee_domain_status,
    evaluate_call_conditions,
)
from pysymex._internal.contracts.runtime.call.diagnostics import (
    binding_failure_diagnostics,
    dependent_postcondition_diagnostics,
)
from pysymex._internal.contracts.value.expressions import expression_for_contract_value

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    import z3

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState


def inject_call_preconditions(
    state: VMState,
    func: Callable[..., object],
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    *,
    include_preconditions: bool = True,
) -> tuple[VMState | None, list[Issue]]:
    """Verify callee preconditions and return the constrained entry state."""
    contract = ContractRegistry.get(func)
    if not contract:
        return state, []
    enabled_preconditions = contract.preconditions if include_preconditions else []
    if not enabled_preconditions and not contract.assumptions:
        return state, []

    try:
        bound = inspect.signature(func).bind(*args, **kwargs)
        bound.apply_defaults()
        arguments = bound.arguments
    except (TypeError, ValueError) as exc:
        return None, binding_failure_diagnostics(
            state,
            func,
            enabled_preconditions,
            contract.assumptions,
            contract.postconditions,
            exc,
        )

    symbols = _call_contract_symbols(arguments)
    evaluation = evaluate_call_conditions(
        state,
        func,
        enabled_preconditions,
        contract.assumptions,
        symbols,
    )
    issues = list(evaluation.issues)
    conditions = list(evaluation.conditions)

    if evaluation.has_unsupported:
        issues.extend(
            dependent_postcondition_diagnostics(
                state,
                func,
                contract.postconditions,
                VerificationResult.UNSUPPORTED,
                evaluation.unsupported_reasons,
            ),
        )
        return None, issues

    domain_status, domain_reasons = callee_domain_status(state, conditions)
    if domain_status is not VerificationResult.VERIFIED and contract.postconditions:
        issues.extend(
            dependent_postcondition_diagnostics(
                state,
                func,
                contract.postconditions,
                domain_status,
                domain_reasons,
            ),
        )
        return None, issues

    for condition in conditions:
        state = state.add_constraint(condition)
    return state, issues


def _call_contract_symbols(arguments: Mapping[str, Any]) -> dict[str, z3.ExprRef]:
    """Return contract-visible Z3 symbols for Python-bound call arguments."""
    symbols: dict[str, z3.ExprRef] = {}
    for name, stack_val in arguments.items():
        expr = expression_for_contract_value(stack_val)
        if expr is not None:
            symbols[name] = expr
    return symbols
