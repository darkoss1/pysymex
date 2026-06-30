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

"""Evaluate ``@assigns`` and ``@pure`` from recorded VM write events.

Both declarations are backed by the path-local modeled write ledger. ``@assigns()``
is the frame-condition spelling for allowed locations; ``@pure`` is the named
no-visible-write spelling and keeps a distinct report kind. Neither obligation
proves determinism, referential transparency, or absence of unsupported native
effects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.contracts.decorator.registry import ContractRegistry
from pysymex._internal.contracts.effects.classification import (
    AssignsEffectPolicy,
    assigns_condition,
    effect_solver_status,
    writes_message,
)
from pysymex._internal.contracts.effects.locations import visible_effect_events
from pysymex._internal.contracts.enums import EffectKind, VerificationResult
from pysymex._internal.contracts.ir.evidence import UnsupportedReason
from pysymex._internal.contracts.ir.obligations import ObligationHook, QueryKind
from pysymex._internal.contracts.obligations.evidence import build_contract_evidence
from pysymex._internal.contracts.runtime.capture import RuntimeContractOutcome
from pysymex._internal.contracts.types import Contract
from pysymex.contracts import ContractKind

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from pysymex._internal.core.effects.events import WriteEvent
    from pysymex._internal.core.state.record import VMState


def check_effect_obligations(
    state: VMState,
    func: Callable[..., object],
    events: Sequence[WriteEvent],
    *,
    visible_roots: frozenset[str] = frozenset(),
) -> None:
    """Classify declared frame and purity obligations for one return path."""
    contract = ContractRegistry.get(func)
    if contract is None:
        return
    visible_events = visible_effect_events(events, visible_roots)
    if contract.assigns_declared:
        _record_assigns_obligation(state, func, contract.assigns_set, visible_events)
    if contract.effect_type is EffectKind.PURE:
        _record_pure_obligation(state, func, visible_events)


def _record_assigns_obligation(
    state: VMState,
    func: Callable[..., object],
    allowed_locations: frozenset[str],
    events: Sequence[WriteEvent],
) -> None:
    """Record evidence for a function frame-condition obligation."""
    condition = assigns_condition(allowed_locations)
    clause = Contract(
        kind=ContractKind.ASSIGNS,
        predicate=condition,
        message=f"Frame condition: {condition}",
    )
    status, message, reasons = AssignsEffectPolicy.classify(state, func, allowed_locations, events)
    evidence = build_contract_evidence(
        clause,
        func,
        hook=ObligationHook.FRAME_EXIT,
        query_kind=QueryKind.FRAME_CONDITION,
        pc=state.pc,
        status=status,
        solver_status=effect_solver_status(status),
        message=message,
        query_constraints=list(state.path_constraints),
        unsupported_reasons=reasons,
    )
    RuntimeContractOutcome.record_evidence(clause, func, evidence)


def _record_pure_obligation(
    state: VMState,
    func: Callable[..., object],
    events: Sequence[WriteEvent],
) -> None:
    """Record evidence for the named no-visible-write obligation."""
    clause = Contract(
        kind=ContractKind.PURE,
        predicate="pure",
        message="Pure function obligation",
    )
    if events:
        status = VerificationResult.VIOLATED
        message = writes_message("Pure function performed modeled writes", events)
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
        solver_status=effect_solver_status(status),
        message=message,
        query_constraints=list(state.path_constraints),
        unsupported_reasons=reasons,
    )
    RuntimeContractOutcome.record_evidence(clause, func, evidence)
