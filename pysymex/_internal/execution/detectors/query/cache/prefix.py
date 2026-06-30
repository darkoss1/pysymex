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

"""Inconclusive-prefix policy for detector SAT queries."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.feasibility import detector_witness_model
from pysymex._internal.execution.detectors.query.cache.decisions import DetectorQueryDecision
from pysymex._internal.execution.detectors.query.constraints import (
    should_try_inconclusive_prefix_witness,
)

if TYPE_CHECKING:
    import z3


def inconclusive_prefix_decision(
    *,
    constraints: list[z3.BoolRef],
    inconclusive_prefix_len: int | None,
) -> DetectorQueryDecision | None:
    """Return an inconclusive-prefix decision, or ``None`` when normal solving should run."""
    if should_try_inconclusive_prefix_witness(
        constraints=constraints,
        inconclusive_prefix_len=inconclusive_prefix_len,
    ):
        return _extended_prefix_decision(constraints)

    if inconclusive_prefix_len is None or len(constraints) != inconclusive_prefix_len:
        return None

    is_sat = detector_witness_model(constraints) is not None
    if is_sat:
        return DetectorQueryDecision(
            result=True,
            result_source="inconclusive_prefix_witness",
            witness_used=True,
        )
    return _unknown_prefix_decision(len(constraints))


def _extended_prefix_decision(constraints: list[z3.BoolRef]) -> DetectorQueryDecision:
    """Try a concrete witness before treating an extended inconclusive prefix as unknown."""
    is_sat = detector_witness_model(constraints) is not None
    if is_sat:
        return DetectorQueryDecision(
            result=True,
            result_source="inconclusive_prefix_witness",
            witness_used=True,
        )
    return _unknown_prefix_decision(len(constraints))


def _unknown_prefix_decision(constraints_count: int) -> DetectorQueryDecision:
    """Return the degraded detector-query result for an inconclusive path prefix."""
    return DetectorQueryDecision(
        result=False,
        result_source="inconclusive_prefix_unknown",
        witness_used=False,
        cacheable=False,
        unknown_reason=(
            "detector query extends an inconclusive path-feasibility "
            f"prefix with {constraints_count} constraint(s)"
        ),
    )
