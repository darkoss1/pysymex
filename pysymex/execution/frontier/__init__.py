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

"""POLAR frontier runtime types.

This package owns resident runtime queue entries, cheap scheduling features,
lazy shadow capsules, checkpoints, and spill gates. Default runtime scheduling
uses resident ``VMState`` payloads plus cheap features; exact CEGIS preview or
evidence application materializes full capsules/checkpoints only when the owner
operation needs proof artifacts.
"""

from __future__ import annotations

from pysymex.execution.frontier.checkpoints import (
    FrontierCheckpoint,
    FrontierReconstructionResult,
    FrontierReconstructionStatus,
    FrontierStateSnapshot,
    build_frontier_checkpoint,
)
from pysymex.execution.frontier.compaction import (
    FrontierCompactionDecision,
    FrontierCompactionStatus,
)
from pysymex.execution.frontier.entries import (
    FrontierMaterializationError,
    FrontierQueueEntry,
    build_frontier_queue_entry,
    materialize_frontier_queue_entry,
)
from pysymex.execution.frontier.modes import FrontierRuntimeMode
from pysymex.execution.frontier.obligations import (
    CapsuleDigest,
    FrontierTelemetry,
    LiveSemanticFootprint,
    ObligationCapsule,
    build_shadow_capsule,
    capsule_matches_state,
    capsule_semantic_digest,
    collect_frontier_telemetry,
    state_structural_hash,
    state_shadow_digest,
)
from pysymex.execution.frontier.proof_index import (
    UnsatCoreCoverage,
    exact_unsat_core_coverage,
)
from pysymex.execution.frontier.spill import (
    FrontierSpillDecision,
    FrontierSpillPolicy,
    FrontierSpillStatus,
)
from pysymex.execution.frontier.store import (
    FrontierRuntimeFeatures,
    FrontierWorkStore,
    FrontierWorkStoreStats,
)

__all__ = [
    "CapsuleDigest",
    "FrontierCheckpoint",
    "FrontierCompactionDecision",
    "FrontierCompactionStatus",
    "FrontierMaterializationError",
    "FrontierQueueEntry",
    "FrontierReconstructionResult",
    "FrontierReconstructionStatus",
    "FrontierStateSnapshot",
    "FrontierTelemetry",
    "FrontierRuntimeMode",
    "FrontierRuntimeFeatures",
    "FrontierSpillDecision",
    "FrontierSpillPolicy",
    "FrontierSpillStatus",
    "FrontierWorkStore",
    "FrontierWorkStoreStats",
    "LiveSemanticFootprint",
    "ObligationCapsule",
    "UnsatCoreCoverage",
    "build_frontier_checkpoint",
    "build_frontier_queue_entry",
    "build_shadow_capsule",
    "capsule_matches_state",
    "capsule_semantic_digest",
    "collect_frontier_telemetry",
    "exact_unsat_core_coverage",
    "materialize_frontier_queue_entry",
    "state_structural_hash",
    "state_shadow_digest",
]
