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

from typing import TYPE_CHECKING

from pysymex._internal.contracts.ir.clauses import (
    ContractClauseIR,
    target_for_callable,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.contracts.types import Contract

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
