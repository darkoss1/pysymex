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

"""Shared builder for declarative cache surface metadata."""

from __future__ import annotations

from pysymex.core.cache.policy import (
    CacheEvidenceKind,
    CacheLayer,
    CacheScope,
    CacheSurface,
)


def cache_surface(
    name: str,
    owner: str,
    layer: CacheLayer,
    scope: CacheScope,
    kind: CacheEvidenceKind,
    key: str,
    values: str,
    invalidation: str,
    *,
    tests: tuple[str, ...],
    benchmarks: tuple[str, ...] = (),
    collision: bool = True,
    inconclusive: bool = False,
    critical: bool = False,
) -> CacheSurface:
    """Create a cache surface entry with project-default safety flags."""
    return CacheSurface(
        name=name,
        owner_module=owner,
        layer=layer,
        scope=scope,
        evidence_kind=kind,
        key_contract=key,
        stored_values=values,
        invalidation_contract=invalidation,
        collision_validation=collision,
        stores_inconclusive=inconclusive,
        performance_critical=critical,
        tests=tests,
        benchmarks=benchmarks,
    )


__all__ = ["cache_surface"]
