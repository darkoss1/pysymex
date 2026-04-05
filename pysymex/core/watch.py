# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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
