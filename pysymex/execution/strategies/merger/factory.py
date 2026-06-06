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

"""Factory for optional join-point state merging during exploration."""

from __future__ import annotations

from pysymex.execution.strategies.merger.types import MergePolicy


def create_state_merger(
    policy: str = "moderate",
    max_constraints: int = 50,
    similarity_threshold: float = 0.7,
):
    """Create a ``StateMerger`` configured by policy name.

    Args:
        policy: ``conservative``, ``moderate``, or ``aggressive`` merge policy.
        max_constraints: Maximum path constraints considered mergeable together.
        similarity_threshold: Structural similarity required for symbolic merge.

    Returns:
        Configured :class:`~pysymex.execution.strategies.merger.state.StateMerger`.
    """
    from pysymex.execution.strategies.merger.state import StateMerger

    policy_map = {
        "conservative": MergePolicy.CONSERVATIVE,
        "moderate": MergePolicy.MODERATE,
        "aggressive": MergePolicy.AGGRESSIVE,
    }
    return StateMerger(
        policy=policy_map.get(policy.lower(), MergePolicy.MODERATE),
        max_constraints_for_merge=max_constraints,
        similarity_threshold=similarity_threshold,
    )
