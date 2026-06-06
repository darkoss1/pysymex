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

"""Scoped raw-Z3 query helpers that preserve inconclusive outcomes."""

from __future__ import annotations

from collections.abc import Sequence

import z3

from pysymex.logger import get_logger

logger = get_logger(__name__)

_SCOPED_QUERY_ERRORS = (z3.Z3Exception, OSError, RuntimeError, ValueError)


def check_scoped_constraints(
    solver: z3.Solver,
    constraints: Sequence[z3.BoolRef],
) -> z3.CheckSatResult:
    """Check constraints in a temporary raw-Z3 scope.

    Returns:
        The raw Z3 check result, with push/add/check/pop/reset failures mapped
        to ``z3.unknown``.
    """
    pushed = False
    result = z3.unknown
    try:
        solver.push()
        pushed = True
        solver.add(*constraints)
        result = solver.check()
    except _SCOPED_QUERY_ERRORS:
        logger.debug("Scoped Z3 query failed; preserving result as UNKNOWN", exc_info=True)
        result = z3.unknown
    finally:
        if pushed:
            try:
                solver.pop()
            except _SCOPED_QUERY_ERRORS:
                logger.debug("Scoped Z3 query cleanup failed; resetting solver", exc_info=True)
                result = z3.unknown
                try:
                    solver.reset()
                except _SCOPED_QUERY_ERRORS:
                    logger.debug("Scoped Z3 query reset failed after cleanup error", exc_info=True)
    return result
