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

"""Build path-local contract obligations from clauses and VM context."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.contracts.frontend.native import native_clause_ir_from_contract
from pysymex._internal.contracts.ir.obligations import ObligationHook, ObligationIR, QueryKind

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    import z3

    from pysymex._internal.contracts.types import Contract


def _constraint_tuple(constraints: Iterable[z3.BoolRef]) -> tuple[z3.BoolRef, ...]:
    """Materialize constraints in deterministic order."""
    return tuple(constraints)


def build_obligation(
    clause: Contract,
    func: Callable[..., object],
    *,
    hook: ObligationHook,
    query_kind: QueryKind,
    pc: int | None,
    formula: z3.BoolRef | None = None,
    query_constraints: Iterable[z3.BoolRef] = (),
) -> ObligationIR:
    """Build an obligation for one contract clause at one execution point."""
    clause_ir = native_clause_ir_from_contract(clause, func)
    constraints = _constraint_tuple(query_constraints)
    return ObligationIR(
        obligation_id=(
            clause_ir.clause_id,
            hook.value,
            query_kind.value,
            pc,
            tuple(map(str, constraints)),
        ),
        clause=clause_ir,
        hook=hook,
        query_kind=query_kind,
        pc=pc,
        formula=formula,
        query_constraints=constraints,
    )
