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

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from typing import cast

import z3

from pysymex.contracts.decorators import ensures, requires
from pysymex.core.solver.constraints import structural_hash
from pysymex.core.types.base import safe_z3_eq

__all__ = [
    "ConflictLearner",
    "ConflictWorker",
]


def _is_z3_bool_list(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, z3.BoolRef) for item in cast("list[object]", value)
    )


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and value > 0


def _is_non_negative_int(value: object) -> bool:
    return isinstance(value, int) and value >= 0


def _is_index_list(value: object) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, int) and item >= 0 for item in cast("list[object]", value)
    )


def _is_index_list_or_none(value: object) -> bool:
    return value is None or _is_index_list(value)


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


def _valid_depth(current_depth: int, max_depth: int) -> bool:
    return current_depth >= 0 and max_depth >= 0


def _is_conflict_learner(value: object) -> bool:
    return isinstance(value, ConflictLearner)


def _is_non_negative_timeout(value: object) -> bool:
    return value is None or (isinstance(value, int | float) and value >= 0)


class ConflictLearner:
    """
    Z3 activation-literal conflict learning and UNSAT-core extractor.

    Translates structural branch contradictions into reusable learned conflicts,
    validating the extracted UNSAT cores on a clean solver instance to prevent
    unsound prunes.
    """

    __slots__ = ("_validated_core_cache", "timeout_ms")

    @requires(_is_positive_int)
    def __init__(self, timeout_ms: int = 5000) -> None:
        if timeout_ms <= 0:
            raise ValueError("Timeout must be a positive integer.")
        self.timeout_ms = timeout_ms
        self._validated_core_cache: OrderedDict[
            int, list[tuple[tuple[z3.BoolRef, ...], list[int]]]
        ] = OrderedDict()

    @property
    @ensures(_is_non_negative_int)
    def validated_core_cache_size(self) -> int:
        """Number of validated conflict learning cache buckets."""
        return len(self._validated_core_cache)

    @requires(_is_z3_bool_list)
    @ensures(_is_index_list_or_none)
    def _cached_validated_core(self, constraints: list[z3.BoolRef]) -> list[int] | None:
        cache_key = structural_hash(constraints)
        bucket = self._validated_core_cache.get(cache_key)
        if bucket is None:
            return None
        self._validated_core_cache.move_to_end(cache_key)
        for cached_constraints, cached_core in bucket:
            if len(cached_constraints) != len(constraints):
                continue
            match = True
            for cached, current in zip(cached_constraints, constraints, strict=True):
                if cached is current or safe_z3_eq(cached, current):
                    continue
                match = False
                break
            if match:
                return list(cached_core)
        return None

    @requires(_is_z3_bool_list)
    @requires(_is_index_list)
    def _store_validated_core(self, constraints: list[z3.BoolRef], core: list[int]) -> None:
        cache_key = structural_hash(constraints)
        entry = (tuple(constraints), list(core))
        bucket = self._validated_core_cache.get(cache_key)
        if bucket is None:
            self._validated_core_cache[cache_key] = [entry]
        else:
            bucket.append(entry)
            self._validated_core_cache.move_to_end(cache_key)
        while len(self._validated_core_cache) > 1024:
            self._validated_core_cache.popitem(last=False)

    @requires(_is_z3_bool_list)
    @requires(_is_index_list)
    @ensures(_is_bool)
    def _validate_core(self, constraints: list[z3.BoolRef], core_indices: list[int]) -> bool:
        if not core_indices:
            return False
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        try:
            solver.add(*[constraints[index] for index in core_indices])
            return solver.check() == z3.unsat
        except (IndexError, z3.Z3Exception):
            return False

    @requires(_is_z3_bool_list)
    @ensures(_is_index_list_or_none)
    def extract_conflict_sync(self, constraints: list[z3.BoolRef]) -> list[int] | None:
        """
        Synchronously extract a verified conflicting constraint subset.

        Wraps each constraint in a pure boolean activation literal.
        Returns a list of indices representing the conflicting constraints, or None if SAT.
        """
        if not constraints:
            return None

        cached = self._cached_validated_core(constraints)
        if cached is not None:
            return cached

        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.set("core.minimize", True)

        activation_literals: list[z3.BoolRef] = []
        literal_to_idx: dict[str, int] = {}

        prefix = f"alpha_{id(self)}"

        for i, constraint in enumerate(constraints):
            alpha = z3.Bool(f"{prefix}_{i}")
            solver.add(z3.Implies(alpha, constraint))
            activation_literals.append(alpha)
            literal_to_idx[str(alpha)] = i

        result = solver.check(*activation_literals)

        if result == z3.unsat:
            core = solver.unsat_core()
            core_indices = [literal_to_idx[str(lit)] for lit in core]
            if self._validate_core(constraints, core_indices):
                self._store_validated_core(constraints, core_indices)
                return core_indices

        return None


class ConflictWorker:
    """
    Synchronous worker wrapping the conflict learner to coordinate SMT checks.

    (Note: Synchronous to avoid cross-thread Z3 C-API violations).
    """

    __slots__ = ("learner",)

    @requires(_is_conflict_learner)
    def __init__(self, learner: ConflictLearner) -> None:
        self.learner = learner

    @requires(_is_z3_bool_list)
    @requires(_valid_depth)
    def dispatch(
        self,
        constraints: list[z3.BoolRef],
        callback: Callable[[list[int] | None], None],
        current_depth: int = 0,
        max_depth: int = 100,
    ) -> None:
        """
        Dispatch conflict extraction.

        Callback is invoked with the conflict indices or None if SAT.
        Enforces a bounded exploration depth to protect against state-explosion.
        """
        if current_depth > max_depth:
            return

        try:
            result = self.learner.extract_conflict_sync(constraints)
        except (IndexError, ValueError, z3.Z3Exception):
            callback(None)
            return
        callback(result)

    @requires(_is_non_negative_timeout)
    def wait_all(self, timeout: float | None = None) -> None:
        """Wait for extraction work to complete. Synchronous interface for testing."""
        _ = timeout
