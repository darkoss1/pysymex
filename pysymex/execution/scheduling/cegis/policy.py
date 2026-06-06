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

"""Deterministic phase-0 CEGIS bid selection."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pysymex.execution.scheduling.cegis.bids import EvidenceBid
from pysymex.execution.scheduling.cegis.budgets import BudgetVector


@dataclass(frozen=True, slots=True)
class SchedulerDecision:
    """Deterministic CEGIS shadow decision."""

    selected_bid: EvidenceBid
    rejected_action_ids: tuple[str, ...]
    active_budget: BudgetVector
    score: float


def select_deterministic_bid(
    bids: Iterable[EvidenceBid],
    *,
    active_budget: BudgetVector,
) -> SchedulerDecision | None:
    """Select the highest-scoring sound bid under ``active_budget``."""
    accepted: list[EvidenceBid] = []
    rejected: list[str] = []
    for bid in bids:
        action = bid.action
        if not action.required_budget.fits_within(active_budget):
            rejected.append(action.action_id)
            continue
        if not action.is_sound_for_selection:
            rejected.append(action.action_id)
            continue
        accepted.append(bid)

    if not accepted:
        return None

    selected = sorted(
        accepted,
        key=lambda bid: (
            -bid.score,
            bid.action.capsule_id,
            bid.action.kind.value,
            bid.action.action_id,
        ),
    )[0]
    return SchedulerDecision(
        selected_bid=selected,
        rejected_action_ids=tuple(rejected),
        active_budget=active_budget,
        score=selected.score,
    )


__all__ = ["SchedulerDecision", "select_deterministic_bid"]
