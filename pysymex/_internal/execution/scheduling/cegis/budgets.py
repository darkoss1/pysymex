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

"""Budget vectors for phase-0 CEGIS shadow scheduling."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BudgetVector:
    """Resource budget vector used as a hard gate by CEGIS."""

    wall_time_ms: float = 0.0
    solver_time_ms: float = 0.0
    resident_units: int = 0
    reconstruction_units: int = 0
    path_budget: int = 0

    def fits_within(self, limit: BudgetVector) -> bool:
        """Return whether this budget can fit within ``limit``."""
        return (
            self.wall_time_ms <= limit.wall_time_ms
            and self.solver_time_ms <= limit.solver_time_ms
            and self.resident_units <= limit.resident_units
            and self.reconstruction_units <= limit.reconstruction_units
            and self.path_budget <= limit.path_budget
        )
