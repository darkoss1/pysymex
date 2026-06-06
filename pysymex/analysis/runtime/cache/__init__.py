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

"""Analysis caching, invalidation, and parallel execution.

Re-exports the analysis cache subsystem: cache keying and hashing,
in-memory LRU and SQLite-backed persistent storage, two-level tiered
composition, invalidation strategies, parallel task orchestration,
and progress reporting.
"""

from pysymex.analysis.runtime.cache.cached import CachedAnalysis
from pysymex.analysis.runtime.cache.models import AnalysisResult, AnalysisTask
from pysymex.analysis.runtime.cache.parallel import ParallelAnalyzer
from pysymex.analysis.runtime.cache.progress import ProgressReporter
from pysymex.analysis.runtime.cache.keying import CacheKey, CacheKeyType
from pysymex.analysis.runtime.cache.keying import hash_bytecode, hash_dict, hash_file, hash_function
from pysymex.analysis.runtime.cache.memory import LRUCache
from pysymex.analysis.runtime.cache.persistent.store import PersistentCache
from pysymex.analysis.runtime.cache.persistent.types import CacheEntry
from pysymex.analysis.runtime.cache.tiered import TieredCache
from pysymex.analysis.runtime.cache.invalidation import (
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
