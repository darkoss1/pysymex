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

"""Path-local contract obligation records."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3

    from pysymex._internal.contracts.ir.clauses import ContractClauseIR


def _empty_constraints() -> tuple[z3.BoolRef, ...]:
    """Return an empty constraint tuple for dataclass defaults."""
    return ()


class ObligationHook(Enum):
    """Execution point that generated a contract obligation."""

    FRAME_ENTRY = "frame_entry"
    CALL_SITE = "call_site"
    FRAME_EXIT = "frame_exit"


class QueryKind(Enum):
    """Contract query intent.

    The query kind describes why a solver query is being issued, not merely that
    a SAT check happened.
    """

    ENTRY_SAT = "entry_sat"
    CALL_PRECONDITION = "call_precondition"
    POSTCONDITION = "postcondition"
    ASSUMPTION = "assumption"
    ASSERTION = "assertion"
    FRAME_CONDITION = "frame_condition"
    PURE_EFFECT = "pure_effect"
    INVARIANT_ENTRY = "invariant_entry"
    INVARIANT_EXIT = "invariant_exit"
    LOOP_BASE = "loop_base"
    LOOP_STEP = "loop_step"


@dataclass(frozen=True, slots=True)
class ObligationIR:
    """One path-local proof or classification obligation."""

    obligation_id: tuple[object, ...]
    clause: ContractClauseIR
    hook: ObligationHook
    query_kind: QueryKind
    pc: int | None
    formula: z3.BoolRef | None = None
    query_constraints: tuple[z3.BoolRef, ...] = field(default_factory=_empty_constraints)
