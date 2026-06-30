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

"""Witness model construction helpers for detector feasibility evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.evidence.errors import EVIDENCE_SOLVER_FAILURES
from pysymex._internal.analysis.evidence.solvers import create_evidence_solver
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = get_logger(__name__)


def substitution_model(
    substitutions: Sequence[tuple[z3.ExprRef, z3.ExprRef]],
    *,
    failure_message: str = "Substitution witness model extraction failed; treating as inconclusive",
) -> z3.ModelRef | None:
    """Return a model for exact substitutions after solver confirmation."""
    solver = create_evidence_solver()
    if solver is None:
        return None
    solver.add(*(left == right for left, right in substitutions))
    try:
        if solver.check() != z3.sat:
            return None
        return solver.model()
    except EVIDENCE_SOLVER_FAILURES:
        logger.debug(failure_message)
        return None
