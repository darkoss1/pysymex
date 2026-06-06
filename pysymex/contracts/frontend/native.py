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

"""Native PySyMex decorator frontend.

This module is the adapter from ``@requires``/``@ensures``/``@assumes`` and
native effect declarations to frontend-neutral ``ContractClauseIR`` records.
It does not compile predicates or decide verification results.
"""

from __future__ import annotations

from collections.abc import Callable

from pysymex.contracts.decorator_registry import get_function_contract
from pysymex.contracts.ir.clauses import (
    ContractClauseIR,
    target_for_callable,
)
from pysymex.contracts.types import Contract, ContractKind, EffectKind

NATIVE_FRONTEND = "native"


def native_clause_ir_from_contract(
    clause: Contract,
    func: Callable[..., object],
    *,
    frontend: str = NATIVE_FRONTEND,
) -> ContractClauseIR:
    """Lower one native ``Contract`` record into frontend-neutral clause IR."""
    target = target_for_callable(func)
    return ContractClauseIR(
        clause_id=(target.identity, clause.kind, clause.condition, clause.line_number, frontend),
        target=target,
        kind=clause.kind,
        predicate=clause.predicate,
        condition=clause.condition,
        message=clause.message,
        severity=clause.severity,
        line_number=clause.line_number,
        frontend=frontend,
    )


def native_function_clause_irs(func: Callable[..., object]) -> tuple[ContractClauseIR, ...]:
    """Return all native function clauses in deterministic proof-pipeline order."""
    contract = get_function_contract(func)
    if contract is None:
        return ()

    clauses: list[ContractClauseIR] = []
    for clause in contract.preconditions:
        clauses.append(native_clause_ir_from_contract(clause, func))
    for clause in contract.assumptions:
        clauses.append(native_clause_ir_from_contract(clause, func))
    for clause in contract.postconditions:
        clauses.append(native_clause_ir_from_contract(clause, func))
    for pc in sorted(contract.loop_invariants):
        for clause in contract.loop_invariants[pc]:
            clauses.append(native_clause_ir_from_contract(clause, func))
    if contract.assigns_declared:
        clauses.append(
            native_clause_ir_from_contract(_assigns_contract(contract.assigns_set), func)
        )
    if contract.effect_type is EffectKind.PURE:
        clauses.append(native_clause_ir_from_contract(_pure_contract(), func))
    return tuple(clauses)


def _assigns_contract(locations: frozenset[str]) -> Contract:
    """Build the native clause record for an ``@assigns`` declaration."""
    condition = _assigns_condition(locations)
    return Contract(
        kind=ContractKind.ASSIGNS,
        predicate=condition,
        message=f"Frame condition: {condition}",
    )


def _pure_contract() -> Contract:
    """Build the native clause record for a ``@pure`` declaration."""
    return Contract(
        kind=ContractKind.PURE,
        predicate="pure",
        message="Pure function obligation",
    )


def _assigns_condition(locations: frozenset[str]) -> str:
    """Return the stable display condition for an assigns declaration."""
    if not locations:
        return "assigns()"
    return "assigns(" + ", ".join(sorted(locations)) + ")"


__all__ = [
    "NATIVE_FRONTEND",
    "native_clause_ir_from_contract",
    "native_function_clause_irs",
]
