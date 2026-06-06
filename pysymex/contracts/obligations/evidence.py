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

"""Construct evidence for contract obligations.

This module is the shared handoff from path-local obligation construction to
typed evidence records. Runtime hooks pass execution context in; report adapters
consume only the returned evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

import z3

from pysymex.contracts.ir.evidence import (
    EvidenceResult,
    SolverStatus,
    TheoryFeature,
    UnsupportedReason,
    evidence_result,
)
from pysymex.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex.contracts.obligations.builder import build_obligation
from pysymex.contracts.types import Contract, VerificationResult


def build_contract_evidence(
    clause: Contract,
    func: Callable[..., object],
    *,
    hook: ObligationHook,
    query_kind: QueryKind,
    pc: int | None,
    status: VerificationResult,
    solver_status: SolverStatus,
    message: str,
    formula: z3.BoolRef | None = None,
    query_constraints: Sequence[z3.BoolRef] = (),
    model: z3.ModelRef | None = None,
    unsupported_reasons: tuple[UnsupportedReason, ...] = (),
    timeout_ms: int | None = None,
    need_model: bool = False,
    theory_profile: tuple[TheoryFeature, ...] = (),
) -> EvidenceResult:
    """Build evidence for one runtime or offline contract check."""
    obligation = build_obligation(
        clause,
        func,
        hook=hook,
        query_kind=query_kind,
        pc=pc,
        formula=formula,
        query_constraints=query_constraints,
    )
    return evidence_result(
        obligation,
        status,
        solver_status,
        message,
        model=model,
        unsupported_reasons=unsupported_reasons,
        timeout_ms=timeout_ms,
        need_model=need_model,
        theory_profile=theory_profile,
    )


def unsupported_reasons_for_exception(exc: BaseException) -> tuple[UnsupportedReason, ...]:
    """Return the precise unsupported reason carried by a lowering exception."""
    reason = getattr(exc, "unsupported_reason", None)
    if isinstance(reason, UnsupportedReason):
        return (reason,)
    return (UnsupportedReason.PREDICATE_LOWERING,)


__all__ = ["build_contract_evidence", "unsupported_reasons_for_exception"]
