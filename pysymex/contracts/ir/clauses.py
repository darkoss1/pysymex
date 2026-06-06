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

"""Normalized contract clause records.

This module owns frontend-neutral clause and target records. Decorators and
external frontends attach metadata in different ways, but frontend adapters must
lower those declarations to ``ContractClauseIR`` before runtime hooks or solvers
reason about them.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib

from pysymex.contracts.types import ContractKind, ContractPredicate, Severity


@dataclass(frozen=True, slots=True)
class ContractTarget:
    """Stable identity for the callable currently associated with a clause."""

    identity: int
    name: str
    qualname: str
    module: str | None


@dataclass(frozen=True, slots=True)
class ContractClauseIR:
    """Frontend-neutral contract clause.

    The predicate is intentionally not a Z3 formula. Lowering and solver query
    planning happen after a path-specific binding environment exists.
    """

    clause_id: tuple[int, ContractKind, str, int | None, str]
    target: ContractTarget
    kind: ContractKind
    predicate: ContractPredicate
    condition: str
    message: str
    severity: Severity
    line_number: int | None
    frontend: str = "native"


def target_for_callable(func: Callable[..., object]) -> ContractTarget:
    """Build a contract target identity from a callable."""
    return ContractTarget(
        identity=id(func),
        name=getattr(func, "__name__", "unknown"),
        qualname=getattr(func, "__qualname__", getattr(func, "__name__", "unknown")),
        module=getattr(func, "__module__", None),
    )


def target_for_source(
    name: str,
    *,
    qualname: str | None = None,
    module: str | None = None,
    line_number: int | None = None,
) -> ContractTarget:
    """Build a deterministic contract target identity from source metadata."""
    resolved_qualname = qualname or name
    key = f"{module or '<unknown>'}:{resolved_qualname}:{line_number or 0}"
    digest = hashlib.blake2b(key.encode("utf-8"), digest_size=8).digest()
    return ContractTarget(
        identity=int.from_bytes(digest, byteorder="big", signed=False),
        name=name,
        qualname=resolved_qualname,
        module=module,
    )


__all__ = [
    "ContractClauseIR",
    "ContractTarget",
    "target_for_callable",
    "target_for_source",
]
