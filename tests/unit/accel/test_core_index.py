# pyright: reportPrivateUsage=false

import pytest
import time
from pysymex.accel.types import CompressedBitmap, CoreMask, PathMask, TheorySignature, InsertStatus
from pysymex.accel.core_index import CoreIndex, CoreCertificate


@pytest.fixture
def core_index() -> CoreIndex:
    return CoreIndex(eviction_threshold_seconds=0.1)


def create_core(core_id: int, atoms: set[int]) -> CoreCertificate:
    return CoreCertificate(
        core_id=core_id,
        atoms=tuple(atoms),
        core_mask=CoreMask(CompressedBitmap(frozenset(atoms))),
        bag_ids=tuple(),
        subtree_id=None,
        separator_signature=None,
        decomposition_id=1,
        theory_signature=TheorySignature.PURE_BOOL,
        normalized_formula_hash="hash",
        smtlib_hash="hash",
        solver_backend="test",
        solver_version="1.0",
        minimized=True,
        rechecked=True,
        solve_time_ms=1.0,
        discovered_at_depth=1,
    )


def test_core_index_add_and_prune(core_index: CoreIndex) -> None:
    core1 = create_core(1, {1, 2})
    status = core_index.insert_core(core1)
    assert status == InsertStatus.ADDED

    path1 = PathMask(CompressedBitmap(frozenset({1, 2, 3})))
    assert core_index.prunes(path1) is True

    path2 = PathMask(CompressedBitmap(frozenset({1, 3})))
    assert core_index.prunes(path2) is False


def test_core_index_subset_rejection(core_index: CoreIndex) -> None:
    core1 = create_core(1, {1, 2})
    core_index.insert_core(core1)

    # A core with {1, 2, 3} is a superset of {1, 2}, should be rejected
    core2 = create_core(2, {1, 2, 3})
    status = core_index.insert_core(core2)
    assert status == InsertStatus.DISCARD_REDUNDANT


def test_core_index_superset_removal(core_index: CoreIndex) -> None:
    core1 = create_core(1, {1, 2, 3})
    core_index.insert_core(core1)

    # A core with {1, 2} is smaller, should replace {1, 2, 3}
    core2 = create_core(2, {1, 2})
    status = core_index.insert_core(core2)
    assert status == InsertStatus.ADDED
    assert len(core_index._cores) == 1
    assert list(core_index._cores)[0].core_id == 2


def test_core_index_eviction(core_index: CoreIndex) -> None:
    core1 = create_core(1, {1, 2})
    core_index.insert_core(core1)

    # Sleep to exceed eviction threshold
    time.sleep(0.15)
    evicted = core_index.evict_stale_cores()
    assert evicted == 1
    assert len(core_index._cores) == 0
