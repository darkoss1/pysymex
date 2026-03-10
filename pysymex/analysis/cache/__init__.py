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
