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

"""Evaluate ``@assigns`` and ``@pure`` from recorded VM write events."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from pysymex.contracts.decorators import get_function_contract
from pysymex.contracts.ir.evidence import SolverStatus, UnsupportedReason
from pysymex.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex.contracts.obligations import build_contract_evidence
from pysymex.contracts.runtime.capture import record_runtime_contract_evidence
from pysymex.contracts.types import Contract, ContractKind, EffectKind, VerificationResult
from pysymex.core.effects.events import WriteEvent
from pysymex.core.state.record import VMState


def check_effect_obligations(
    state: VMState,
    func: Callable[..., object],
    events: Sequence[WriteEvent],
) -> None:
    """Classify declared frame and purity obligations for one return path."""
    contract = get_function_contract(func)
    if contract is None:
        return
    if contract.assigns_declared:
        _record_assigns_obligation(state, func, contract.assigns_set, events)
    if contract.effect_type is EffectKind.PURE:
        _record_pure_obligation(state, func, events)


def _record_assigns_obligation(
    state: VMState,
    func: Callable[..., object],
    allowed_locations: frozenset[str],
    events: Sequence[WriteEvent],
) -> None:
    """Record evidence for a function frame-condition obligation."""
    condition = _assigns_condition(allowed_locations)
    clause = Contract(
        kind=ContractKind.ASSIGNS,
        predicate=condition,
        message=f"Frame condition: {condition}",
    )
    status, message, reasons = _classify_assigns(allowed_locations, events)
    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.FRAME_EXIT,
        query_kind=QueryKind.FRAME_CONDITION,
        pc=state.pc,
        status=status,
        solver_status=_effect_solver_status(status),
        message=message,
        query_constraints=list(state.path_constraints),
        unsupported_reasons=reasons,
    )
    record_runtime_contract_evidence(clause, func, evidence)


def _record_pure_obligation(
    state: VMState,
    func: Callable[..., object],
    events: Sequence[WriteEvent],
) -> None:
    """Record evidence for a declared purity obligation."""
    clause = Contract(
        kind=ContractKind.PURE,
        predicate="pure",
        message="Pure function obligation",
    )
    if events:
        status = VerificationResult.VIOLATED
        message = _writes_message("Pure function performed modeled writes", events)
        reasons = (UnsupportedReason.EFFECT_WRITE,)
    else:
        status = VerificationResult.VERIFIED
        message = "Pure function performed no modeled writes"
        reasons = ()
    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.FRAME_EXIT,
        query_kind=QueryKind.PURE_EFFECT,
        pc=state.pc,
        status=status,
        solver_status=_effect_solver_status(status),
        message=message,
        query_constraints=list(state.path_constraints),
        unsupported_reasons=reasons,
    )
    record_runtime_contract_evidence(clause, func, evidence)


def _classify_assigns(
    allowed_locations: frozenset[str],
    events: Sequence[WriteEvent],
) -> tuple[VerificationResult, str, tuple[UnsupportedReason, ...]]:
    """Return the evidence classification for one ``@assigns`` declaration."""
    if not events:
        return VerificationResult.VERIFIED, "Frame condition observed no modeled writes", ()
    if not allowed_locations:
        return (
            VerificationResult.VIOLATED,
            _writes_message("Frame condition forbids all modeled writes", events),
            (UnsupportedReason.EFFECT_WRITE,),
        )
    violating_precise = [
        event for event in events if event.precise and event.location not in allowed_locations
    ]
    if violating_precise:
        return (
            VerificationResult.VIOLATED,
            _writes_message("Frame condition wrote outside declared locations", violating_precise),
            (UnsupportedReason.EFFECT_WRITE,),
        )
    imprecise = [event for event in events if not event.precise]
    if imprecise:
        return (
            VerificationResult.UNKNOWN,
            _writes_message("Frame condition depends on imprecise alias ownership", imprecise),
            (UnsupportedReason.ALIAS_IMPRECISION,),
        )
    return VerificationResult.VERIFIED, "Frame condition allowed all modeled writes", ()


def _effect_solver_status(status: VerificationResult) -> SolverStatus:
    """Map non-solver effect classifications into evidence solver status."""
    if status is VerificationResult.UNKNOWN:
        return SolverStatus.UNKNOWN
    return SolverStatus.NOT_RUN


def _assigns_condition(locations: frozenset[str]) -> str:
    """Return the display condition for an assigns declaration."""
    if not locations:
        return "assigns()"
    return "assigns(" + ", ".join(sorted(locations)) + ")"


def _writes_message(prefix: str, events: Sequence[WriteEvent]) -> str:
    """Return a compact write-event diagnostic message."""
    locations = ", ".join(f"{event.location} via {event.source}" for event in events[:4])
    if len(events) > 4:
        locations = f"{locations}, +{len(events) - 4} more"
    return f"{prefix}: {locations}"


__all__ = ["check_effect_obligations"]
