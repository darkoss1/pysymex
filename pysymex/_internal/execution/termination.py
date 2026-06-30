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

"""Termination proof result types and bounded-execution classification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


class TerminationStatus(Enum):
    """Recorded result category for a termination proof attempt."""

    TERMINATES = auto()
    UNKNOWN = auto()


@dataclass
class TerminationProof:
    """Recorded termination proof status and optional display metadata.

    ``ranking_function`` is retained as opaque metadata for result formatting
    when another caller supplies an object with an ``expression`` attribute.

    Limitations:
        ``TERMINATES`` from the public wrapper means bounded symbolic execution
        completed its explored paths without degradation. It is not a general
        ranking-function or liveness proof.
    """

    status: TerminationStatus
    ranking_function: object | None = None
    bound: int | None = None
    counterexample: dict[str, object] | None = None
    message: str = ""


def termination_proof_from_bounded_execution(
    *,
    paths_explored: int,
    paths_completed: int,
    paths_pruned: int = 0,
    degraded_passes: Sequence[str] = (),
) -> TerminationProof:
    """Classify bounded symbolic execution evidence as termination or unknown.

    Returns ``TERMINATES`` only when at least one path completed, every explored
    path was either completed or pruned as infeasible, and no degraded pass was
    recorded. Resource limits, solver uncertainty, unsupported semantics, havoc,
    and unaccounted paths remain ``UNKNOWN``.
    """
    if degraded_passes:
        return TerminationProof(
            status=TerminationStatus.UNKNOWN,
            message=(
                "Termination inconclusive: bounded execution degraded "
                f"({_format_degraded_passes(degraded_passes)})"
            ),
        )
    if paths_explored <= 0:
        return TerminationProof(
            status=TerminationStatus.UNKNOWN,
            message="Termination inconclusive: no symbolic paths were explored",
        )
    if paths_completed <= 0:
        return TerminationProof(
            status=TerminationStatus.UNKNOWN,
            message="Termination inconclusive: no symbolic paths completed",
        )

    accounted_paths = paths_completed + paths_pruned
    if accounted_paths < paths_explored:
        missing_paths = paths_explored - accounted_paths
        return TerminationProof(
            status=TerminationStatus.UNKNOWN,
            message=(
                "Termination inconclusive: "
                f"{missing_paths} explored path(s) neither completed nor pruned"
            ),
        )

    pruned_suffix = f"; {paths_pruned} infeasible path(s) pruned" if paths_pruned else ""
    return TerminationProof(
        status=TerminationStatus.TERMINATES,
        message=(
            "Bounded symbolic execution completed all accounted paths "
            f"({paths_completed} completed{pruned_suffix}) without degradation"
        ),
    )


def _format_degraded_passes(degraded_passes: Sequence[str]) -> str:
    """Return a stable compact display string for degradation labels."""
    return ", ".join(dict.fromkeys(degraded_passes))
