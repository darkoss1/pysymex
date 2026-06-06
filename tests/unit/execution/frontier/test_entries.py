from __future__ import annotations

from typing import cast

import pytest

from pysymex.core.state.record import VMState
from pysymex.execution.frontier import (
    FrontierMaterializationError,
    FrontierStateSnapshot,
    build_frontier_checkpoint,
    build_frontier_queue_entry,
    materialize_frontier_queue_entry,
    state_shadow_digest,
)


def test_frontier_queue_entry_keeps_direct_state_when_compact_mode_disabled() -> None:
    """Shadow/default modes can queue the direct VMState payload."""
    state = VMState(pc=5)

    entry = build_frontier_queue_entry(
        state,
        checkpoint=None,
        compact_queueing=False,
    )

    assert entry.is_compact is False
    assert materialize_frontier_queue_entry(entry) is state


def test_frontier_queue_entry_reconstructs_compact_checkpoint() -> None:
    """Runtime compact queueing materializes an exact checkpoint on demand."""
    state = VMState(pc=7, path_id=3, depth=2)
    checkpoint = build_frontier_checkpoint(state, capsule_id="entry-compact")

    entry = build_frontier_queue_entry(
        state,
        checkpoint=checkpoint,
        compact_queueing=True,
    )
    materialized = materialize_frontier_queue_entry(entry)

    assert entry.is_compact is True
    assert materialized is not state
    assert state_shadow_digest(materialized) == state_shadow_digest(state)


def test_frontier_queue_entry_requires_checkpoint_for_compact_mode() -> None:
    """Compact queueing cannot silently fall back to direct state storage."""
    with pytest.raises(ValueError, match="requires a checkpoint"):
        build_frontier_queue_entry(
            VMState(pc=1),
            checkpoint=None,
            compact_queueing=True,
        )


def test_frontier_queue_entry_reports_reconstruction_mismatch() -> None:
    """Materialization fails explicitly when the compact snapshot drifts."""
    checkpoint = build_frontier_checkpoint(VMState(pc=2), capsule_id="entry-mismatch")
    snapshot = cast("FrontierStateSnapshot", object.__getattribute__(checkpoint, "_snapshot"))
    object.__setattr__(snapshot, "pc", 42)
    entry = build_frontier_queue_entry(
        VMState(pc=2),
        checkpoint=checkpoint,
        compact_queueing=True,
    )

    with pytest.raises(FrontierMaterializationError) as exc_info:
        materialize_frontier_queue_entry(entry)

    assert exc_info.value.capsule_id == "entry-mismatch"
