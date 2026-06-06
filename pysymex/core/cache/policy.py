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

"""Typed cache policy contracts and manifest validation helpers.

The runtime cache implementations remain owned by their domain modules. This
module owns shared review types and invariant checks used to keep cache
coverage, performance gates, and soundness expectations explicit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from importlib import import_module
from typing import cast


class CacheLayer(Enum):
    """Architectural layer that owns a cache surface."""

    CORE = "core"
    SOLVER = "solver"
    EXECUTION = "execution"
    ANALYSIS_RUNTIME = "analysis-runtime"
    CONTRACTS = "contracts"
    SANDBOX = "sandbox"
    MODELS = "models"


class CacheScope(Enum):
    """Lifetime and sharing boundary for cached entries."""

    PROCESS = "process"
    SOLVER_INSTANCE = "solver-instance"
    EXECUTION_SESSION = "execution-session"
    EXECUTOR_INSTANCE = "executor-instance"
    ANALYSIS_RUNTIME = "analysis-runtime"
    STATE_INSTANCE = "state-instance"
    PERSISTENT = "persistent"
    DOMAIN_LOCAL = "domain-local"


class CacheEvidenceKind(Enum):
    """Kind of information stored by a cache surface."""

    DERIVED_METADATA = "derived-metadata"
    SEMANTIC_RESULT = "semantic-result"
    RUNTIME_ARTIFACT = "runtime-artifact"
    PERSISTENT_ARTIFACT = "persistent-artifact"
    PERFORMANCE_HINT = "performance-hint"


@dataclass(frozen=True, slots=True)
class CacheSurface:
    """Review metadata for one cache implementation.

    ``collision_validation`` means the owner validates a structural or hash key
    against exact inputs before reusing semantic evidence. Semantic-result
    caches must not store timeout, unknown, or inconclusive answers as proof.
    """

    name: str
    owner_module: str
    layer: CacheLayer
    scope: CacheScope
    evidence_kind: CacheEvidenceKind
    key_contract: str
    stored_values: str
    invalidation_contract: str
    collision_validation: bool
    stores_inconclusive: bool
    performance_critical: bool
    tests: tuple[str, ...]
    benchmarks: tuple[str, ...] = ()

    @property
    def stores_semantic_evidence(self) -> bool:
        """Return true when cached values affect feasibility or issue certainty."""
        return self.evidence_kind is CacheEvidenceKind.SEMANTIC_RESULT


@dataclass(frozen=True, slots=True)
class CacheCoverageSummary:
    """Aggregate cache manifest coverage counters."""

    total_surfaces: int
    semantic_evidence_surfaces: int
    tested_surfaces: int
    benchmarked_surfaces: int
    performance_critical_surfaces: int
    collision_validated_surfaces: int
    inconclusive_rejecting_semantic_surfaces: int


def _cache_surfaces() -> tuple[CacheSurface, ...]:
    """Load the cache manifest without creating an import-time cycle."""
    manifest = import_module("pysymex.core.cache.manifest")
    return cast("tuple[CacheSurface, ...]", getattr(manifest, "CACHE_SURFACES"))


def cache_surface_by_name(name: str) -> CacheSurface | None:
    """Return a cache surface by stable manifest name."""
    for surface in _cache_surfaces():
        if surface.name == name:
            return surface
    return None


def cache_surfaces_by_layer(layer: CacheLayer) -> tuple[CacheSurface, ...]:
    """Return cache surfaces owned by an architectural layer."""
    return tuple(surface for surface in _cache_surfaces() if surface.layer is layer)


def semantic_cache_surfaces() -> tuple[CacheSurface, ...]:
    """Return surfaces that cache semantic evidence."""
    return tuple(surface for surface in _cache_surfaces() if surface.stores_semantic_evidence)


def cache_coverage_summary() -> CacheCoverageSummary:
    """Return aggregate coverage metrics for the manifest."""
    surfaces = _cache_surfaces()
    semantic_surfaces = semantic_cache_surfaces()
    return CacheCoverageSummary(
        total_surfaces=len(surfaces),
        semantic_evidence_surfaces=len(semantic_surfaces),
        tested_surfaces=sum(1 for surface in surfaces if surface.tests),
        benchmarked_surfaces=sum(1 for surface in surfaces if surface.benchmarks),
        performance_critical_surfaces=sum(
            1 for surface in surfaces if surface.performance_critical
        ),
        collision_validated_surfaces=sum(1 for surface in surfaces if surface.collision_validation),
        inconclusive_rejecting_semantic_surfaces=sum(
            1 for surface in semantic_surfaces if not surface.stores_inconclusive
        ),
    )


def validate_cache_manifest() -> tuple[str, ...]:
    """Return cache manifest invariant violations, or an empty tuple when valid."""
    errors: list[str] = []
    seen_names: set[str] = set()
    for surface in _cache_surfaces():
        if surface.name in seen_names:
            errors.append(f"duplicate cache surface name: {surface.name}")
        seen_names.add(surface.name)
        if not surface.owner_module:
            errors.append(f"{surface.name} has no owner module")
        if not surface.tests:
            errors.append(f"{surface.name} has no test coverage entry")
        if surface.performance_critical and not surface.benchmarks:
            errors.append(f"{surface.name} is performance-critical without a benchmark")
        if surface.stores_semantic_evidence and surface.stores_inconclusive:
            errors.append(f"{surface.name} stores inconclusive semantic evidence")
        if surface.stores_semantic_evidence and not surface.collision_validation:
            errors.append(f"{surface.name} caches semantic evidence without collision validation")
    return tuple(errors)


__all__ = [
    "CacheCoverageSummary",
    "CacheEvidenceKind",
    "CacheLayer",
    "CacheScope",
    "CacheSurface",
    "cache_coverage_summary",
    "cache_surface_by_name",
    "cache_surfaces_by_layer",
    "semantic_cache_surfaces",
    "validate_cache_manifest",
]
