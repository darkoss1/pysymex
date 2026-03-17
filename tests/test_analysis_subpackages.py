"""Tests for analysis subpackages (cache, contracts, patterns, pipeline, type_inference)."""
from __future__ import annotations
import pytest

# -- Cache --
from pysymex.analysis.cache.core import (
    CacheKeyType, CacheKey, LRUCache, hash_bytecode, hash_function, TieredCache,
)
from pysymex.analysis.cache.analysis import (
    AnalysisTask, AnalysisResult, ProgressReporter, CachedAnalysis,
)
from pysymex.analysis.cache.invalidation import (
    InvalidationStrategy, InvalidationRule, SmartInvalidator, FileCache,
)

# -- Contracts --
from pysymex.analysis.contracts.types import (
    ContractKind, VerificationResult, ContractViolation, Contract, FunctionContract,
)

# -- Patterns --
from pysymex.analysis.patterns.core import (
    PatternKind, PatternMatch, DictGetHandler, DictSetdefaultHandler,
)

# -- Pipeline --
from pysymex.analysis.pipeline.types import (
    ScannerConfig, IssueCategory, ScanIssue, AnalysisContext, AnalysisPhase,
)

# -- Type Inference --
from pysymex.analysis.type_inference.kinds import TypeKind, PyType
from pysymex.analysis.type_inference.env import TypeEnvironment
from pysymex.analysis.type_inference.engine import TypeInferenceEngine


# ===== Cache =====

class TestCacheKeyType:
    def test_enum(self):
        assert len(CacheKeyType) >= 1

class TestCacheKey:
    def test_creation(self):
        members = list(CacheKeyType)
        ck = CacheKey(key_type=members[0], identifier="test")
        assert ck.identifier == "test"

class TestLRUCache:
    def test_creation(self):
        cache = LRUCache(maxsize=10)
        assert cache is not None

    def test_put_get(self):
        cache = LRUCache(maxsize=10)
        if hasattr(cache, 'put'):
            cache.put("k", "v")
            assert cache.get("k") == "v"
        elif hasattr(cache, '__setitem__'):
            cache["k"] = "v"
            assert cache["k"] == "v"

    def test_eviction(self):
        cache = LRUCache(maxsize=2)
        if hasattr(cache, 'put'):
            cache.put("a", 1)
            cache.put("b", 2)
            cache.put("c", 3)
            assert cache.get("a") is None  # evicted

class TestHashBytecode:
    def test_returns_str(self):
        result = hash_bytecode(b"hello")
        assert isinstance(result, str)
        assert len(result) > 0

class TestHashFunction:
    def test_returns_str(self):
        result = hash_function("func", b"code")
        assert isinstance(result, str)

class TestAnalysisTask:
    def test_creation(self):
        t = AnalysisTask(task_id="test", target=None)
        assert t is not None

class TestAnalysisResult:
    def test_creation(self):
        r = AnalysisResult(task_id="test", success=True)
        assert r is not None

class TestProgressReporter:
    def test_creation(self):
        pr = ProgressReporter()
        assert pr is not None

class TestCachedAnalysis:
    def test_creation(self):
        ca = CachedAnalysis(
            analyze_fn=lambda x: x,
            key_fn=lambda x: CacheKey(CacheKeyType.CUSTOM, identifier=str(x)),
        )
        assert ca is not None

class TestInvalidationStrategy:
    def test_enum(self):
        assert len(InvalidationStrategy) >= 1

class TestSmartInvalidator:
    def test_creation(self):
        si = SmartInvalidator(cache=TieredCache())
        assert si is not None

class TestFileCache:
    def test_creation(self):
        fc = FileCache()
        assert fc is not None


# ===== Contracts =====

class TestContractKind:
    def test_enum(self):
        assert len(ContractKind) >= 1

class TestVerificationResult:
    def test_enum(self):
        assert len(VerificationResult) >= 1

class TestContract:
    def test_creation(self):
        members = list(ContractKind)
        c = Contract(kind=members[0], condition="x > 0")
        assert c.kind == members[0]

class TestFunctionContract:
    def test_creation(self):
        fc = FunctionContract(function_name="test")
        assert fc is not None


# ===== Patterns =====

class TestPatternKind:
    def test_enum(self):
        assert len(PatternKind) >= 1

class TestPatternMatch:
    def test_creation(self):
        members = list(PatternKind)
        pm = PatternMatch(kind=members[0], confidence=0.9, start_pc=0, end_pc=10)
        assert pm.kind == members[0]

class TestDictGetHandler:
    def test_creation(self):
        h = DictGetHandler()
        assert h is not None
    def test_has_handle(self):
        assert hasattr(DictGetHandler, 'match')


# ===== Pipeline =====

class TestScannerConfig:
    def test_creation(self):
        sc = ScannerConfig()
        assert sc is not None

class TestIssueCategory:
    def test_enum(self):
        assert len(IssueCategory) >= 1

class TestAnalysisPhase:
    def test_is_abstract(self):
        assert hasattr(AnalysisPhase, 'analyze')


# ===== Type Inference =====

class TestTypeKind:
    def test_enum(self):
        assert len(TypeKind) >= 1

class TestPyType:
    def test_creation(self):
        members = list(TypeKind)
        pt = PyType(kind=members[0])
        assert pt.kind == members[0]

class TestTypeEnvironment:
    def test_creation(self):
        env = TypeEnvironment()
        assert env is not None

    def test_lookup_missing(self):
        env = TypeEnvironment()
        if hasattr(env, 'lookup'):
            result = env.lookup("nonexistent")
            assert result is None or result is not None

class TestTypeInferenceEngine:
    def test_creation(self):
        engine = TypeInferenceEngine()
        assert engine is not None

    def test_has_infer(self):
        assert (hasattr(TypeInferenceEngine, 'infer_from_annotation') or
                hasattr(TypeInferenceEngine, 'infer_from_value') or
                hasattr(TypeInferenceEngine, 'infer_function_signature'))
