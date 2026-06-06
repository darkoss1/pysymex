from __future__ import annotations

import importlib.util
from pathlib import Path

from pysymex.core.cache.policy import CacheLayer
from pysymex.core.cache.policy import cache_coverage_summary
from pysymex.core.cache.policy import cache_surface_by_name
from pysymex.core.cache.policy import cache_surfaces_by_layer
from pysymex.core.cache.policy import semantic_cache_surfaces
from pysymex.core.cache.policy import validate_cache_manifest
from pysymex.core.cache.manifest import CACHE_SURFACES

REPO_ROOT = Path(__file__).resolve().parents[3]

KNOWN_AUDITED_CACHE_OWNER_MODULES = {
    "pysymex.analysis.detectors.feasibility",
    "pysymex.analysis.runtime.cache.memory",
    "pysymex.analysis.runtime.cache.persistent.store",
    "pysymex.analysis.static.cross_function.summary_cache",
    "pysymex.contracts.formula_cache",
    "pysymex.core.bytecode",
    "pysymex.core.cache.code_objects",
    "pysymex.core.solver.constraints.contradictions",
    "pysymex.core.solver.constraints.hashing",
    "pysymex.core.solver.constraints.literals",
    "pysymex.core.solver.constraints.theory",
    "pysymex.core.solver.engine.result_cache",
    "pysymex.core.solver.engine.check_cache_methods",
    "pysymex.core.solver.engine.translation",
    "pysymex.core.solver.independence.cache",
    "pysymex.core.types.containers.bytes",
    "pysymex.core.types.scalars.value.helpers",
    "pysymex.deps",
    "pysymex.execution.detectors.query.cache",
    "pysymex.execution.engine.bytecode_metadata",
    "pysymex.execution.executors.executor.cache.keys",
    "pysymex.execution.opcodes.common.control.feasibility",
    "pysymex.models.stdlib.functools.cache",
    "pysymex.sandbox.bridge.cache",
    "pysymex.sandbox.isolation.windows.appcontainer.runtime.cache",
}


def test_cache_manifest_invariants_hold() -> None:
    assert validate_cache_manifest() == ()


def test_cache_manifest_names_are_unique_and_owners_are_discoverable() -> None:
    names = [surface.name for surface in CACHE_SURFACES]
    assert len(names) == len(set(names))

    missing_owners = [
        surface.owner_module
        for surface in CACHE_SURFACES
        if importlib.util.find_spec(surface.owner_module) is None
    ]
    assert missing_owners == []

    missing_test_paths = [
        test_path
        for surface in CACHE_SURFACES
        for test_path in surface.tests
        if not (REPO_ROOT / test_path).exists()
    ]
    assert missing_test_paths == []


def test_cache_manifest_declares_audited_source_owners() -> None:
    owners = {surface.owner_module for surface in CACHE_SURFACES}

    assert KNOWN_AUDITED_CACHE_OWNER_MODULES.issubset(owners)


def test_semantic_cache_surfaces_reject_inconclusive_evidence() -> None:
    semantic_names = {surface.name for surface in semantic_cache_surfaces()}

    assert {
        "solver.quick_contradiction",
        "solver.sat_result",
        "solver.check_result",
        "solver.unsat_subset",
        "execution.detector_query",
    }.issubset(semantic_names)
    assert all(not surface.stores_inconclusive for surface in semantic_cache_surfaces())
    assert all(surface.collision_validation for surface in semantic_cache_surfaces())


def test_cache_manifest_tracks_performance_critical_surfaces() -> None:
    critical = {surface.name: surface for surface in CACHE_SURFACES if surface.performance_critical}

    assert {
        "core.exception_entries",
        "core.instruction_tuple",
        "execution.line_mapping",
        "solver.constraint_literals_and_hashes",
        "solver.exact_bool_literal",
        "solver.sat_result",
        "solver.unsat_subset",
        "solver.ast_translation",
    }.issubset(critical)
    assert all(surface.benchmarks for surface in critical.values())


def test_cache_coverage_summary_counts_manifest_coverage() -> None:
    summary = cache_coverage_summary()

    assert summary.total_surfaces == len(CACHE_SURFACES)
    assert summary.tested_surfaces == len(CACHE_SURFACES)
    assert summary.semantic_evidence_surfaces == len(semantic_cache_surfaces())
    assert summary.inconclusive_rejecting_semantic_surfaces == summary.semantic_evidence_surfaces
    assert summary.benchmarked_surfaces >= summary.performance_critical_surfaces


def test_cache_surface_lookup_and_layer_filtering_are_stable() -> None:
    assert cache_surface_by_name("solver.sat_result") is not None
    assert cache_surface_by_name("missing") is None

    solver_names = {surface.name for surface in cache_surfaces_by_layer(CacheLayer.SOLVER)}
    assert "solver.sat_result" in solver_names
    assert "execution.line_mapping" not in solver_names
