# pysymex: Python Symbolic Execution & Formal Verification
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

"""Persistent caching and parallel analysis for pysymex.

Hub module — re-exports from:
  cache_core        : CacheKeyType, CacheKey, hash_*, LRU/Persistent/TieredCache
  cache_analysis    : AnalysisTask, AnalysisResult, ProgressReporter, ParallelAnalyzer, CachedAnalysis
  cache_invalidation: InvalidationStrategy, InvalidationRule, SmartInvalidator, FileCache
"""

from pysymex.analysis.cache.analysis import (
    AnalysisResult,
    AnalysisTask,
    CachedAnalysis,
    ParallelAnalyzer,
    ProgressReporter,
)
from pysymex.analysis.cache.core import (
    CacheEntry,
    CacheKey,
    CacheKeyType,
    LRUCache,
    PersistentCache,
    TieredCache,
    hash_bytecode,
    hash_dict,
    hash_file,
    hash_function,
)
from pysymex.analysis.cache.invalidation import (
    FileCache,
    InvalidationRule,
    InvalidationStrategy,
    SmartInvalidator,
)

__all__ = [
    "AnalysisResult",
    "AnalysisTask",
    "CacheEntry",
    "CacheKey",
    "CacheKeyType",
    "CachedAnalysis",
    "FileCache",
    "InvalidationRule",
    "InvalidationStrategy",
    "LRUCache",
    "ParallelAnalyzer",
    "PersistentCache",
    "ProgressReporter",
    "SmartInvalidator",
    "TieredCache",
    "hash_bytecode",
    "hash_dict",
    "hash_file",
    "hash_function",
]
