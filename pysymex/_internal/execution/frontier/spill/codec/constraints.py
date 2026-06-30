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

"""SMT2 path-constraint encoding for frontier spill payloads."""

from __future__ import annotations

import z3


def constraints_payload(
    constraints: tuple[z3.BoolRef, ...],
) -> str | None | UnsupportedConstraintsSentinel:
    """Encode solver constraints as deterministic SMT2 assertions."""
    if not constraints:
        return None
    try:
        solver = z3.Solver()
        solver.add(*constraints)
        return solver.to_smt2()
    except z3.Z3Exception:
        return UNSUPPORTED_CONSTRAINTS


class UnsupportedConstraintsSentinel:
    """Sentinel for constraints that must not cross the spill boundary."""


UNSUPPORTED_CONSTRAINTS = UnsupportedConstraintsSentinel()
