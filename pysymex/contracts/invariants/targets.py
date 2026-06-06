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

"""Class invariant target discovery and obligation counting.

This module owns the mapping from a verified callable to its declaring class
and applicable invariant clauses. It does not evaluate predicates or format
reports.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from pysymex.contracts.invariants.policy import (
    DEFAULT_INVARIANT_POLICY,
    InvariantCheckPoint,
    InvariantPolicy,
)
from pysymex.contracts.types import Contract, ContractKind


@dataclass(frozen=True, slots=True)
class InvariantTarget:
    """Invariant clauses and checkpoints associated with one callable target."""

    function: Callable[..., object]
    owner_type: type[object]
    clauses: tuple[Contract, ...]
    checkpoints: tuple[InvariantCheckPoint, ...]


def invariant_target_for_callable(
    func: Callable[..., object],
    *,
    policy: InvariantPolicy = DEFAULT_INVARIANT_POLICY,
) -> InvariantTarget | None:
    """Return invariant metadata for *func*, if a declaring class is discoverable."""
    owner_type = owner_type_for_callable(func)
    if owner_type is None:
        return None
    clauses = class_invariants_for_type(owner_type)
    if not clauses:
        return None
    checkpoints = policy.checkpoints_for_method(getattr(func, "__name__", ""))
    if not checkpoints:
        return None
    return InvariantTarget(func, owner_type, clauses, checkpoints)


def class_invariants_for_callable(func: Callable[..., object]) -> tuple[Contract, ...]:
    """Return class invariant clauses discoverable from *func*."""
    owner_type = owner_type_for_callable(func)
    if owner_type is None:
        return ()
    return class_invariants_for_type(owner_type)


def class_invariants_for_type(owner_type: type[object]) -> tuple[Contract, ...]:
    """Return invariant clauses attached to *owner_type* without mutating registries."""
    raw_invariants = getattr(owner_type, "__invariants__", None)
    if not isinstance(raw_invariants, list):
        return ()
    invariant_items = cast("list[object]", raw_invariants)
    return tuple(
        invariant
        for invariant in invariant_items
        if isinstance(invariant, Contract) and invariant.kind is ContractKind.INVARIANT
    )


def invariant_obligation_count_for_callable(
    func: Callable[..., object],
    *,
    policy: InvariantPolicy = DEFAULT_INVARIANT_POLICY,
) -> int:
    """Return how many root invariant obligations *func* should generate."""
    target = invariant_target_for_callable(func, policy=policy)
    if target is None:
        return 0
    return len(target.clauses) * len(target.checkpoints)


def has_invariant_exit_obligations(
    func: Callable[..., object],
    *,
    policy: InvariantPolicy = DEFAULT_INVARIANT_POLICY,
) -> bool:
    """Return whether *func* needs invariant checks on normal frame exit."""
    target = invariant_target_for_callable(func, policy=policy)
    return target is not None and InvariantCheckPoint.EXIT in target.checkpoints


def owner_type_for_callable(func: Callable[..., object]) -> type[object] | None:
    """Return the class that owns *func* when it can be discovered safely."""
    owner = getattr(func, "__self__", None)
    if isinstance(owner, type):
        return cast("type[object]", owner)
    if owner is not None:
        return cast("type[object]", type(owner))

    qualname = getattr(func, "__qualname__", "")
    module = inspect.getmodule(func)
    if module is None or "<locals>" in qualname:
        return None

    candidate: object = module
    for part in qualname.split(".")[:-1]:
        candidate = getattr(candidate, part, None)
        if candidate is None:
            return None
    if isinstance(candidate, type):
        return candidate
    return None


__all__ = [
    "InvariantTarget",
    "class_invariants_for_callable",
    "class_invariants_for_type",
    "has_invariant_exit_obligations",
    "invariant_obligation_count_for_callable",
    "invariant_target_for_callable",
    "owner_type_for_callable",
]
