"""Backward-compatibility shim — watch module moved to pysymex.watch.

This stub re-exports everything from the new location so existing
``from pysymex.core.watch import …`` statements keep working.
"""

from pysymex.watch import (
    AnalysisCache,
    DependencyTracker,
    FileEvent,
    FileEventType,
    FileState,
    FileWatcher,
    IncrementalAnalyzer,
    WatchModeRunner,
)

__all__ = [
    "AnalysisCache",
    "DependencyTracker",
    "FileEvent",
    "FileEventType",
    "FileState",
    "FileWatcher",
    "IncrementalAnalyzer",
    "WatchModeRunner",
]
