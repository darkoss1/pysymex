from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.frontier.checkpoint.snapshot.record import FrontierStateSnapshot
from pysymex._internal.execution.frontier.compaction import FrontierCompactionStatus
from pysymex._internal.execution.frontier.entries import realize_frontier_queue_entry
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from pysymex._internal.execution.frontier.obligations.capsules import build_shadow_capsule
from pysymex._internal.execution.frontier.obligations.digests import state_shadow_digest
from pysymex._internal.execution.frontier.store.core import FrontierWorkStore
from pysymex._internal.execution.frontier.store.core import (
    FrontierWorkStore as FrontierWorkStoreOwner,
)


def test_frontier_work_store_public_export_points_to_direct_owner() -> None:
    assert FrontierWorkStore is FrontierWorkStoreOwner


def test_frontier_work_store_records_shadow_payloads() -> None:
    """The frontier store owns live entries and eager shadow-mode telemetry."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_SHADOW)
    state = VMState(pc=3, path_id=4, depth=2)

    store.add_state(0, state)

    assert len(store) == 1
    assert 0 in store
    assert tuple(store.live_state_ids) == (0,)
    assert store.capsules[0].capsule_id == "path:0"
    assert store.checkpoints == {}
    assert realize_frontier_queue_entry(store.entries[0]) is state
    stats = store.collect_stats()
    assert stats.enabled is True
    assert stats.compact_queueing_enabled is False
    assert stats.checkpoint_count == 0
    assert stats.telemetry.capsule_count == 1
    assert stats.capsule_digest_mismatch_count == 0
    assert stats.reconstruction_mismatch_count == 0

    checkpoint = store.ensure_checkpoint(0)

    assert checkpoint is not None
    assert checkpoint.capsule.capsule_id == "path:0"
    assert store.collect_stats().checkpoint_count == 1


def test_frontier_work_store_runtime_mode_keeps_resident_entries() -> None:
    """Runtime mode records proof telemetry without compacting every executable state."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(pc=8, path_id=2, depth=1)

    store.add_state(0, state)

    assert store.checkpoints == {}
    checkpoint = store.ensure_checkpoint(0)
    assert checkpoint is not None
    assert checkpoint.capsule.capsule_id == "path:0"

    selected = store.pop_materialized(0)

    assert selected is not None
    assert selected is state
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert len(store) == 0
    stats = store.collect_stats()
    assert stats.compact_queueing_enabled is False
    assert stats.telemetry.capsule_count == 0


def test_frontier_work_store_compacts_runtime_entry_to_exact_checkpoint() -> None:
    """Runtime entries can drop resident payloads behind exact checkpoints."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(pc=8, path_id=2, depth=1, local_vars={"x": 1})
    store.add_state(0, state)

    decision = store.request_compaction(0)

    assert decision.status is FrontierCompactionStatus.COMPACTED
    assert decision.can_compact is True
    assert decision.compacted_entry is store.entries[0]
    assert store.entries[0].is_compact is True
    stats = store.collect_stats()
    assert stats.compacted_entry_count == 1
    assert stats.compaction_denied_count == 0

    selected = store.pop_materialized(0)

    assert selected is not None
    assert selected is not state
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert len(store) == 0


def test_frontier_work_store_compaction_denies_missing_and_compact_entries() -> None:
    """Compaction is explicit and fail-closed for stale or already compact work."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(pc=2)
    store.add_state(0, state)

    missing = store.request_compaction(99)
    first = store.request_compaction(0)
    second = store.request_compaction(0)

    assert missing.status is FrontierCompactionStatus.NOT_LIVE
    assert first.status is FrontierCompactionStatus.COMPACTED
    assert second.status is FrontierCompactionStatus.ALREADY_COMPACT
    stats = store.collect_stats()
    assert stats.compacted_entry_count == 1
    assert stats.compaction_denied_count == 2


def test_frontier_work_store_discard_does_not_materialize_lazy_checkpoint() -> None:
    """Certificate-pruned resident entries can discard lazy checkpoints without reconstruction."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    store.add_state(0, VMState(pc=2))
    checkpoint = store.ensure_checkpoint(0)
    assert checkpoint is not None
    snapshot = cast("FrontierStateSnapshot", object.__getattribute__(checkpoint, "_snapshot"))
    object.__setattr__(snapshot, "pc", 99)

    store.discard(0)

    assert len(store) == 0
    assert store.collect_stats().reconstruction_mismatch_count == 0


def test_frontier_work_store_counts_lazy_checkpoint_digest_mismatch() -> None:
    """Lazy checkpoint requests fail closed when capsule digests disagree."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(pc=2)
    store.add_state(0, state)
    capsules = cast("dict[int, object]", object.__getattribute__(store, "_capsules"))
    capsules[0] = build_shadow_capsule(VMState(pc=99), capsule_id="path:0")

    assert store.ensure_checkpoint(0) is None

    stats = store.collect_stats()
    assert stats.capsule_digest_mismatch_count == 1
    assert stats.reconstruction_mismatch_count == 0
