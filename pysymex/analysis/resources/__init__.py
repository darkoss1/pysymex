"""Resource analysis package — leak detection and lifecycle checking.

Submodules
----------
analysis   Resource leak detection, context-manager analysis, lock safety
lifecycle  State-machine–based resource lifecycle checker
"""

from __future__ import annotations

from pysymex.analysis.resources.analysis import (
    ResourceAnalyzer,
)
from pysymex.analysis.resources.lifecycle import (
    FileResourceChecker,
    LockResourceChecker,
    ResourceIssue,
    ResourceIssueKind,
    ResourceKind,
    ResourceLifecycleChecker,
    ResourceState,
    ResourceStateMachine,
    StateTransition,
    TrackedResource,
)

__all__ = [
    "FileResourceChecker",
    "LockResourceChecker",
    "ResourceAnalyzer",
    "ResourceIssue",
    "ResourceIssueKind",
    "ResourceKind",
    "ResourceLifecycleChecker",
    "ResourceState",
    "ResourceStateMachine",
    "StateTransition",
    "TrackedResource",
]
