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

"""Central Z3 configuration used by PySymex solver owners.

This module owns the small set of Z3 knobs that have been measured as the
current safe baseline for PySymex. It deliberately avoids public profile
surface area until a candidate profile improves runtime without increasing
``UNKNOWN`` or degraded scan outcomes.
"""

from __future__ import annotations

from typing import Final

import z3

from pysymex.logger import get_logger

logger = get_logger(__name__)

# Z3 resource limit units per millisecond of effective PySymex query timeout.
Z3_RLIMIT_UNITS_PER_TIMEOUT_MS: Final = 2500


def configure_process_z3(timeout_ms: int) -> None:
    """Apply process-wide Z3 settings shared by incremental solver instances."""
    try:
        z3.set_param("parallel.enable", False)
        z3.set_param("sat.threads", 1)
    except (z3.Z3Exception, OSError, ValueError):
        logger.debug("Z3 process thread configuration unsupported on this host", exc_info=True)
    z3.set_param("timeout", timeout_ms)


def create_configured_solver(timeout_ms: int) -> z3.Solver:
    """Return a Z3 solver configured with the PySymex baseline settings."""
    solver = z3.Solver()
    apply_solver_base_config(solver, timeout_ms)
    return solver


def apply_solver_base_config(solver: z3.Solver, timeout_ms: int) -> None:
    """Apply per-solver baseline settings without changing process-global state."""
    solver.set("timeout", timeout_ms)
    solver.set("auto_config", False)
    try:
        solver.set("threads", 1)
    except (z3.Z3Exception, OSError, ValueError):
        logger.debug("Z3 solver thread option unsupported on this host", exc_info=True)


def rlimit_for_timeout_ms(timeout_ms: int) -> int:
    """Return the Z3 resource limit for an effective timeout."""
    return int(timeout_ms * Z3_RLIMIT_UNITS_PER_TIMEOUT_MS)


__all__ = [
    "Z3_RLIMIT_UNITS_PER_TIMEOUT_MS",
    "apply_solver_base_config",
    "configure_process_z3",
    "create_configured_solver",
    "rlimit_for_timeout_ms",
]
