"""Backward-compatibility shim — watch module moved to pysymex.watch.

This stub re-exports everything from the new location so existing
``from pysymex.core.watch import …`` statements keep working.
"""

from pysymex.watch import (
    FileEventType,
    FileEvent,
    FileState,
    FileWatcher,
    AnalysisCache,
    IncrementalAnalyzer,
    WatchModeRunner,
    DependencyTracker,
)

__all__ = [
    "FileEventType",
    "FileEvent",
    "FileState",
    "FileWatcher",
    "AnalysisCache",
    "IncrementalAnalyzer",
    "WatchModeRunner",
    "DependencyTracker",
]
