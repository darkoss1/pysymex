# pysymex: Python Symbolic Execution & Formal Verification
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

import time
from typing import Callable, Dict, List, Optional

import z3


class MUSGatekeeper:
    """
    Hybrid MUS Gatekeeper for pysymex v2.
    Uses Z3 Activation-Literal Core Extraction to find Minimal Unsatisfiable Subsets (MUS).

    This replaces flawed message-passing algorithms (which fail on mixed arithmetic)
    with precise structural contradiction extraction, providing a mathematically
    sound foundation for structural path pruning.
    """

    __slots__ = ("timeout_ms",)

    def __init__(self, timeout_ms: int = 5000) -> None:
        self.timeout_ms = timeout_ms

    def extract_mus_sync(self, constraints: List[z3.BoolRef]) -> Optional[List[int]]:
        """
        Synchronously extracts the MUS from a list of Z3 constraints.
        Wraps each constraint in a pure boolean activation literal.
        Returns a list of indices representing the conflicting constraints, or None if SAT.
        """
        if not constraints:
            return None

        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.set("core.minimize", True)

        activation_literals: List[z3.BoolRef] = []
        literal_to_idx: Dict[str, int] = {}

        prefix = f"alpha_{id(self)}_{time.perf_counter_ns()}"

        for i, constraint in enumerate(constraints):
            alpha = z3.Bool(f"{prefix}_{i}")
            solver.add(z3.Implies(alpha, constraint))
            activation_literals.append(alpha)
            literal_to_idx[str(alpha)] = i

        result = solver.check(*activation_literals)

        if result == z3.unsat:
            core = solver.unsat_core()
            return [literal_to_idx[str(lit)] for lit in core]

        return None


class AsyncMUSWorker:
    """
    Asynchronous Core Learning worker for the Hybrid MUS Gatekeeper.
    (Note: Converted to synchronous execution to prevent Z3 C-API cross-thread access violations).
    """

    __slots__ = ("gatekeeper",)

    def __init__(self, gatekeeper: MUSGatekeeper) -> None:
        self.gatekeeper = gatekeeper

    def dispatch(
        self,
        constraints: List[z3.BoolRef],
        callback: Callable[[Optional[List[int]]], None],
        current_depth: int = 0,
        max_depth: int = 100,
    ) -> None:
        """
        Dispatches MUS extraction.
        Callback is invoked with the result (List of indices if UNSAT, else None).
        Applies a bounded lookahead depth (K) to prevent unbounded state exploration.
        """
        if current_depth > max_depth:
            return

        try:
            result = self.gatekeeper.extract_mus_sync(constraints)
            callback(result)
        except Exception as exc:
            import logging

            logging.getLogger(__name__).debug("MUS extraction error: %s", exc)
            callback(None)

    def wait_all(self, timeout: Optional[float] = None) -> None:
        """Waits for all active extraction threads to complete. Used for synchronization and testing."""
        pass
