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

"""Fixed phase-stat default schemas for execution sessions."""

from __future__ import annotations


def default_phase_timers() -> dict[str, float]:
    """Return the fixed phase-timer schema used in execution results."""
    return {
        "execute_step": 0.0,
        "process_execution_result": 0.0,
        "path_feasibility": 0.0,
    }


def default_phase_counts() -> dict[str, int]:
    """Return the fixed phase-count schema used in execution diagnostics."""
    return {
        "execute_step": 0,
        "process_execution_result": 0,
        "path_feasibility": 0,
    }
