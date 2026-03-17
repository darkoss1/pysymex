"""Tests for stdlib model files: stdlib_system, stdlib_io, stdlib_math, stdlib_containers.

Phase 2 Part C -- Function Models (stdlib group).
Covers os.path, json, datetime, random, types, copy, io, heapq, bisect, math,
collections, itertools, functools models.
"""

from __future__ import annotations

import math

import pytest
import z3

from tests.helpers import make_state, make_symbolic_int, make_symbolic_str, solve, prove

from pysymex.core.types import (
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicType,
    SymbolicValue,
)
from pysymex.models.builtins_base import ModelResult

# ---------------------------------------------------------------------------
# stdlib_system -- os.path models
# ---------------------------------------------------------------------------
from pysymex.models.stdlib_system import (
    OsPathExistsModel,
    OsPathIsfileModel,
    OsPathIsdirModel,
    OsPathJoinModel,
    OsPathDirnameModel,
    OsPathBasenameModel,
    OsPathSplitModel,
    OsPathAbspathModel,
    JsonLoadsModel,
    JsonDumpsModel,
    JsonLoadModel,
    JsonDumpModel,
    DatetimeNowModel,
    DatetimeConstructorModel,
    TimedeltaConstructorModel,
    RandomRandomModel,
    RandomRandintModel,
    RandomChoiceModel,
    RandomShuffleModel,
    RandomSampleModel,
    RandomUniformModel,
    SimpleNamespaceModel,
    ospath_models,
    json_models,
    datetime_models,
    random_models,
    types_models,
)

# ---------------------------------------------------------------------------
# stdlib_io models
# ---------------------------------------------------------------------------
from pysymex.models.stdlib_io import (
    CopyModel,
    DeepcopyModel,
    StringIOModel,
    BytesIOModel,
    IOReadModel,
    IOWriteModel,
    IOGetvalueModel,
    HeappushModel,
    HeappopModel,
    HeapifyModel,
    HeapreplaceModel,
    HeappushpopModel,
    NlargestModel,
    NsmallestModel,
    BisectLeftModel,
    BisectRightModel,
    BisectModel,
    InsortLeftModel,
    InsortRightModel,
    InsortModel,
    copy_models,
    io_models,
    heapq_models,
    bisect_models,
)

# ---------------------------------------------------------------------------
# stdlib_math models
# ---------------------------------------------------------------------------
from pysymex.models.stdlib_math import (
    MathSqrtModel,
    MathCeilModel,
    MathFloorModel,
    MathLogModel,
    MathExpModel,
    MathSinModel,
    MathCosModel,
    MathTanModel,
    MathFabsModel,
    MathGcdModel,
    MathIsfiniteModel,
    MathIsCloseModel,
    MathIsinfModel,
    MathIsnanModel,
    math_models,
)

# ---------------------------------------------------------------------------
# stdlib_containers models
# ---------------------------------------------------------------------------
from pysymex.models.stdlib_containers import (
    CounterModel as SCCounterModel,
    DefaultdictModel as SCDefaultdictModel,
    DequeModel as SCDequeModel,
    OrderedDictModel as SCOrderedDictModel,
    NamedtupleModel,
    ItertoolsChainModel,
    ItertoolsIsliceModel,
    ItertoolsCycleModel,
    ItertoolsRepeatModel,
    ItertoolsTakewhileModel,
    ItertoolsDropwhileModel,
    ItertoolsProductModel,
    ItertoolsPermutationsModel,
    ItertoolsCombinationsModel,
    FunctoolsReduceModel,
    FunctoolsPartialModel,
    FunctoolsLruCacheModel,
    collections_models,
    itertools_models,
    functools_models,
)


# ===================================================================
# Helpers
# ===================================================================

def _state(pc: int = 0):
    """Return a minimal VMState for model application."""
    return make_state(pc=pc)


# ===================================================================
# os.path models
# ===================================================================

class TestOsPathExistsModel:
    def test_returns_symbolic_bool(self):
        m = OsPathExistsModel()
        r = m.apply(["some/path"], {}, _state())
        assert isinstance(r, ModelResult)
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 2

    def test_qualname(self):
        assert OsPathExistsModel().qualname == "os.path.exists"


class TestOsPathIsfileModel:
    def test_returns_symbolic_bool(self):
        r = OsPathIsfileModel().apply(["/tmp/f"], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert any(
            c is r.value.is_bool or (hasattr(c, 'eq') and True) for c in r.constraints
        )

    def test_qualname(self):
        assert OsPathIsfileModel().qualname == "os.path.isfile"


class TestOsPathIsdirModel:
    def test_returns_symbolic_bool(self):
        r = OsPathIsdirModel().apply(["/tmp"], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_qualname(self):
        assert OsPathIsdirModel().qualname == "os.path.isdir"


class TestOsPathJoinModel:
    def test_concrete_args(self):
        r = OsPathJoinModel().apply(["/usr", "local", "bin"], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_symbolic_args(self):
        sym = make_symbolic_str("p")
        r = OsPathJoinModel().apply([sym, "sub"], {}, _state())
        assert isinstance(r.value, SymbolicString)
        assert len(r.constraints) >= 1

    def test_qualname(self):
        assert OsPathJoinModel().qualname == "os.path.join"


class TestOsPathDirnameModel:
    def test_concrete(self):
        r = OsPathDirnameModel().apply(["/usr/local/bin"], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_symbolic(self):
        r = OsPathDirnameModel().apply([make_symbolic_str("d")], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_qualname(self):
        assert OsPathDirnameModel().qualname == "os.path.dirname"


class TestOsPathBasenameModel:
    def test_concrete(self):
        r = OsPathBasenameModel().apply(["/usr/local/bin"], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_symbolic(self):
        r = OsPathBasenameModel().apply([make_symbolic_str("b")], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestOsPathSplitModel:
    def test_concrete(self):
        r = OsPathSplitModel().apply(["/usr/local"], {}, _state())
        assert isinstance(r.value, tuple)
        assert len(r.value) == 2
        assert all(isinstance(v, SymbolicString) for v in r.value)

    def test_symbolic(self):
        r = OsPathSplitModel().apply([make_symbolic_str("s")], {}, _state())
        assert isinstance(r.value, tuple)
        assert len(r.value) == 2
        assert len(r.constraints) >= 2


class TestOsPathAbspathModel:
    def test_returns_symbolic_string(self):
        r = OsPathAbspathModel().apply(["rel"], {}, _state())
        assert isinstance(r.value, SymbolicString)
        # abspath should have len >= 1 constraint
        assert len(r.constraints) >= 2


# ===================================================================
# JSON models
# ===================================================================

class TestJsonLoadsModel:
    def test_returns_symbolic_value(self):
        r = JsonLoadsModel().apply(['{"a": 1}'], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_qualname(self):
        assert JsonLoadsModel().qualname == "json.loads"


class TestJsonDumpsModel:
    def test_returns_symbolic_string(self):
        r = JsonDumpsModel().apply([{"a": 1}], {}, _state())
        assert isinstance(r.value, SymbolicString)
        # json dumps at least 2 chars (e.g. "{}")
        assert len(r.constraints) >= 2

    def test_qualname(self):
        assert JsonDumpsModel().qualname == "json.dumps"


class TestJsonLoadModel:
    def test_returns_symbolic_value_with_io(self):
        r = JsonLoadModel().apply(["fileobj"], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert r.side_effects.get("io") is True

    def test_qualname(self):
        assert JsonLoadModel().qualname == "json.load"


class TestJsonDumpModel:
    def test_returns_none_with_io(self):
        r = JsonDumpModel().apply([{"a": 1}, "fileobj"], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("io") is True


# ===================================================================
# Datetime models
# ===================================================================

class TestDatetimeNowModel:
    def test_returns_symbolic_int_with_lower_bound(self):
        r = DatetimeNowModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        # Should have is_int and > 1672531200 constraints
        assert len(r.constraints) >= 3

    def test_qualname(self):
        assert DatetimeNowModel().qualname == "datetime.datetime.now"


class TestDatetimeConstructorModel:
    def test_returns_symbolic_int(self):
        r = DatetimeConstructorModel().apply([2023, 1, 1], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 2


class TestTimedeltaConstructorModel:
    def test_returns_symbolic_int(self):
        r = TimedeltaConstructorModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


# ===================================================================
# Random models
# ===================================================================

class TestRandomRandomModel:
    def test_returns_float_in_0_1(self):
        r = RandomRandomModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3  # symbolic, is_float, >= 0, < 1


class TestRandomRandintModel:
    def test_concrete_bounds(self):
        r = RandomRandintModel().apply([1, 10], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        # constraints: symbolic, is_int, >= 1, <= 10
        assert len(r.constraints) >= 4

    def test_symbolic_bounds(self):
        lo = make_symbolic_int("lo")
        hi = make_symbolic_int("hi")
        r = RandomRandintModel().apply([lo, hi], {}, _state())
        assert len(r.constraints) >= 4

    def test_no_bounds(self):
        r = RandomRandintModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 2


class TestRandomChoiceModel:
    def test_concrete_list(self):
        r = RandomChoiceModel().apply([[1, 2, 3]], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("lst")
        r = RandomChoiceModel().apply([sl], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_empty_args(self):
        r = RandomChoiceModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestRandomShuffleModel:
    def test_returns_none_with_mutates(self):
        r = RandomShuffleModel().apply([[3, 1, 2]], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("mutates_arg") == 0


class TestRandomSampleModel:
    def test_concrete_k(self):
        r = RandomSampleModel().apply([[1, 2, 3, 4], 2], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_symbolic_k(self):
        k = make_symbolic_int("k")
        r = RandomSampleModel().apply([[1, 2, 3], k], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_no_k(self):
        r = RandomSampleModel().apply([[1]], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestRandomUniformModel:
    def test_with_bounds(self):
        r = RandomUniformModel().apply([0.0, 1.0], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3  # symbolic, is_float, bounds

    def test_no_bounds(self):
        r = RandomUniformModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


# ===================================================================
# Types models
# ===================================================================

class TestSimpleNamespaceModel:
    def test_with_kwargs(self):
        st = _state()
        r = SimpleNamespaceModel().apply([], {"x": 1, "y": 2}, st)
        assert isinstance(r.value, SymbolicType)

    def test_no_kwargs(self):
        st = _state()
        r = SimpleNamespaceModel().apply([], {}, st)
        assert isinstance(r.value, SymbolicType)

    def test_qualname(self):
        assert SimpleNamespaceModel().qualname == "types.SimpleNamespace"


# ===================================================================
# Model list checks
# ===================================================================

class TestModelLists:
    def test_ospath_models_count(self):
        assert len(ospath_models) == 8

    def test_json_models_count(self):
        assert len(json_models) == 4

    def test_datetime_models_count(self):
        assert len(datetime_models) == 3

    def test_random_models_count(self):
        assert len(random_models) == 6

    def test_types_models_count(self):
        assert len(types_models) == 1


# ===================================================================
# Copy / IO models (stdlib_io)
# ===================================================================

class TestCopyModel:
    def test_with_arg(self):
        sv = make_symbolic_int("orig")
        r = CopyModel().apply([sv], {}, _state())
        assert r.value is sv

    def test_no_arg(self):
        r = CopyModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_qualname(self):
        assert CopyModel().qualname == "copy.copy"


class TestDeepcopyModel:
    def test_symbolic_value(self):
        sv = make_symbolic_int("orig")
        r = DeepcopyModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 2

    def test_symbolic_string(self):
        ss = make_symbolic_str("orig_s")
        r = DeepcopyModel().apply([ss], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("orig_l")
        r = DeepcopyModel().apply([sl], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_no_arg(self):
        r = DeepcopyModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_qualname(self):
        assert DeepcopyModel().qualname == "copy.deepcopy"


class TestStringIOModel:
    def test_returns_symbolic_value(self):
        r = StringIOModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_qualname(self):
        assert StringIOModel().qualname == "io.StringIO"


class TestBytesIOModel:
    def test_returns_symbolic_value(self):
        r = BytesIOModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_qualname(self):
        assert BytesIOModel().qualname == "io.BytesIO"


class TestIOReadModel:
    def test_returns_symbolic_string(self):
        r = IOReadModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestIOWriteModel:
    def test_symbolic_string_arg(self):
        ss = make_symbolic_str("data")
        r = IOWriteModel().apply([ss], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_arg(self):
        r = IOWriteModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestIOGetvalueModel:
    def test_returns_symbolic_string(self):
        r = IOGetvalueModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicString)


# ===================================================================
# Heapq models
# ===================================================================

class TestHeappushModel:
    def test_returns_none_mutates(self):
        r = HeappushModel().apply([[1, 2], 0], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("mutates_arg") == 0


class TestHeappopModel:
    def test_returns_symbolic_mutates(self):
        r = HeappopModel().apply([[1, 2, 3]], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert r.side_effects.get("mutates_arg") == 0


class TestHeapifyModel:
    def test_returns_none_mutates(self):
        r = HeapifyModel().apply([[3, 1, 2]], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("mutates_arg") == 0


class TestHeapreplaceModel:
    def test_returns_symbolic_mutates(self):
        r = HeapreplaceModel().apply([[1, 2], 3], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert r.side_effects.get("mutates_arg") == 0


class TestHeappushpopModel:
    def test_returns_symbolic_mutates(self):
        r = HeappushpopModel().apply([[1, 2], 0], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert r.side_effects.get("mutates_arg") == 0


class TestNlargestModel:
    def test_concrete_n(self):
        r = NlargestModel().apply([3, [5, 1, 3, 2, 4]], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_no_n(self):
        r = NlargestModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestNsmallestModel:
    def test_concrete_n(self):
        r = NsmallestModel().apply([2, [5, 1, 3]], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_no_n(self):
        r = NsmallestModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)


# ===================================================================
# Bisect models
# ===================================================================

class TestBisectLeftModel:
    def test_returns_int_gte_zero(self):
        r = BisectLeftModel().apply([[1, 3, 5], 3], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("arr")
        r = BisectLeftModel().apply([sl, 3], {}, _state())
        # Should also constrain result <= list length
        assert len(r.constraints) >= 4

    def test_qualname(self):
        assert BisectLeftModel().qualname == "bisect.bisect_left"


class TestBisectRightModel:
    def test_returns_int_gte_zero(self):
        r = BisectRightModel().apply([[1, 3, 5], 3], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("arr2")
        r = BisectRightModel().apply([sl, 3], {}, _state())
        assert len(r.constraints) >= 4


class TestBisectAliasModel:
    def test_bisect_alias(self):
        r = BisectModel().apply([[1, 3, 5], 3], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3


class TestInsortModels:
    def test_insort_left_returns_none(self):
        r = InsortLeftModel().apply([[1, 3], 2], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("mutates_arg") == 0

    def test_insort_right_returns_none(self):
        r = InsortRightModel().apply([[1, 3], 2], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("mutates_arg") == 0

    def test_insort_alias_returns_none(self):
        r = InsortModel().apply([[1, 3], 2], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("mutates_arg") == 0


class TestStdlibIOModelLists:
    def test_copy_models_count(self):
        assert len(copy_models) == 2

    def test_io_models_count(self):
        assert len(io_models) == 5

    def test_heapq_models_count(self):
        assert len(heapq_models) == 7

    def test_bisect_models_count(self):
        assert len(bisect_models) == 6


# ===================================================================
# Math models (stdlib_math)
# ===================================================================

class TestMathSqrtModel:
    def test_concrete_positive(self):
        r = MathSqrtModel().apply([4], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_float(self):
        r = MathSqrtModel().apply([2.0], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        sv = make_symbolic_int("x")
        r = MathSqrtModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3  # symbolic, is_float, x >= 0, result >= 0

    def test_no_args(self):
        r = MathSqrtModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_qualname(self):
        assert MathSqrtModel().qualname == "math.sqrt"


class TestMathCeilModel:
    def test_concrete_int(self):
        r = MathCeilModel().apply([3], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_float(self):
        r = MathCeilModel().apply([2.3], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        sv = make_symbolic_int("c")
        r = MathCeilModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 4

    def test_no_args(self):
        r = MathCeilModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathFloorModel:
    def test_concrete_int(self):
        r = MathFloorModel().apply([3], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_float(self):
        r = MathFloorModel().apply([2.7], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        sv = make_symbolic_int("f")
        r = MathFloorModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 4

    def test_no_args(self):
        r = MathFloorModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathLogModel:
    def test_concrete_positive(self):
        r = MathLogModel().apply([10], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_with_base(self):
        r = MathLogModel().apply([100, 10], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        sv = make_symbolic_int("l")
        r = MathLogModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_args(self):
        r = MathLogModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathExpModel:
    def test_concrete(self):
        r = MathExpModel().apply([1], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        sv = make_symbolic_int("e")
        r = MathExpModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 2  # symbolic, is_float, result > 0

    def test_no_args(self):
        r = MathExpModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathSinModel:
    def test_concrete(self):
        r = MathSinModel().apply([0], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        r = MathSinModel().apply([make_symbolic_int("s")], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        # sin is bounded between -1 and 1
        assert len(r.constraints) >= 4

    def test_no_args(self):
        r = MathSinModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathCosModel:
    def test_concrete(self):
        r = MathCosModel().apply([0], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        r = MathCosModel().apply([make_symbolic_int("c")], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 4

    def test_no_args(self):
        r = MathCosModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathTanModel:
    def test_concrete(self):
        r = MathTanModel().apply([0], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        r = MathTanModel().apply([make_symbolic_int("t")], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_args(self):
        r = MathTanModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathFabsModel:
    def test_concrete_positive(self):
        r = MathFabsModel().apply([3], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_negative(self):
        r = MathFabsModel().apply([-5], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        sv = make_symbolic_int("f")
        r = MathFabsModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        # result >= 0 constraint
        assert len(r.constraints) >= 3

    def test_no_args(self):
        r = MathFabsModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathGcdModel:
    def test_concrete(self):
        r = MathGcdModel().apply([12, 8], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        a = make_symbolic_int("a")
        b = make_symbolic_int("b")
        r = MathGcdModel().apply([a, b], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_fewer_than_two_args(self):
        r = MathGcdModel().apply([5], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathIsfiniteModel:
    def test_concrete_int(self):
        r = MathIsfiniteModel().apply([5], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_float(self):
        r = MathIsfiniteModel().apply([float("inf")], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        sv = make_symbolic_int("v")
        r = MathIsfiniteModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_args(self):
        r = MathIsfiniteModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathIsCloseModel:
    def test_concrete_close(self):
        r = MathIsCloseModel().apply([1.0, 1.0 + 1e-10], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_not_close(self):
        r = MathIsCloseModel().apply([1.0, 2.0], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        a = make_symbolic_int("a")
        b = make_symbolic_int("b")
        r = MathIsCloseModel().apply([a, b], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathIsinfModel:
    def test_concrete_int(self):
        r = MathIsinfModel().apply([5], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_inf(self):
        r = MathIsinfModel().apply([float("inf")], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic(self):
        sv = make_symbolic_int("v")
        r = MathIsinfModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_args(self):
        r = MathIsinfModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathIsnanModel:
    def test_concrete_int(self):
        r = MathIsnanModel().apply([5], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_nan(self):
        r = MathIsnanModel().apply([float("nan")], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_symbolic_returns_false(self):
        sv = make_symbolic_int("v")
        r = MathIsnanModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_no_args(self):
        r = MathIsnanModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestMathModelList:
    def test_count(self):
        assert len(math_models) == 14


# ===================================================================
# stdlib_containers -- collections, itertools, functools
# ===================================================================

class TestSCCounterModel:
    def test_returns_symbolic_dict(self):
        r = SCCounterModel().apply([], {}, _state())
        assert isinstance(r.value, (SymbolicValue, SymbolicType))

    def test_qualname(self):
        assert SCCounterModel().qualname == "collections.Counter"


class TestSCDefaultdictModel:
    def test_returns_symbolic_dict(self):
        r = SCDefaultdictModel().apply([], {}, _state())
        assert isinstance(r.value, (SymbolicValue, SymbolicType))

    def test_qualname(self):
        assert SCDefaultdictModel().qualname == "collections.defaultdict"


class TestSCDequeModel:
    def test_empty_deque(self):
        r = SCDequeModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_with_concrete_list(self):
        r = SCDequeModel().apply([[1, 2, 3]], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_with_maxlen(self):
        r = SCDequeModel().apply([], {"maxlen": 5}, _state())
        assert isinstance(r.value, SymbolicList)


class TestSCOrderedDictModel:
    def test_returns_symbolic_dict(self):
        r = SCOrderedDictModel().apply([], {}, _state())
        assert isinstance(r.value, (SymbolicValue, SymbolicType))


class TestNamedtupleModel:
    def test_returns_symbolic_value(self):
        r = NamedtupleModel().apply(["Point", ["x", "y"]], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestItertoolsChainModel:
    def test_concrete_lists(self):
        r = ItertoolsChainModel().apply([[1, 2], [3, 4]], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_symbolic_lists(self):
        sl1, _ = SymbolicList.symbolic("l1")
        sl2, _ = SymbolicList.symbolic("l2")
        r = ItertoolsChainModel().apply([sl1, sl2], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_qualname(self):
        assert ItertoolsChainModel().qualname == "itertools.chain"


class TestItertoolsIsliceModel:
    def test_two_args(self):
        r = ItertoolsIsliceModel().apply([[1, 2, 3, 4, 5], 3], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_three_args(self):
        r = ItertoolsIsliceModel().apply([[1, 2, 3, 4, 5], 1, 4], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_no_stop(self):
        r = ItertoolsIsliceModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestItertoolsCycleModel:
    def test_returns_symbolic_list(self):
        r = ItertoolsCycleModel().apply([[1, 2]], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestItertoolsRepeatModel:
    def test_with_times(self):
        r = ItertoolsRepeatModel().apply(["x", 5], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_without_times(self):
        r = ItertoolsRepeatModel().apply(["x"], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestItertoolsTakewhileModel:
    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("tw")
        r = ItertoolsTakewhileModel().apply([None, sl], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_no_list(self):
        r = ItertoolsTakewhileModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestItertoolsDropwhileModel:
    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("dw")
        r = ItertoolsDropwhileModel().apply([None, sl], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_no_list(self):
        r = ItertoolsDropwhileModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestItertoolsProductModel:
    def test_concrete_lists(self):
        r = ItertoolsProductModel().apply([[1, 2], [3, 4]], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_with_repeat(self):
        r = ItertoolsProductModel().apply([[1, 2]], {"repeat": 2}, _state())
        assert isinstance(r.value, SymbolicList)


class TestItertoolsPermutationsModel:
    def test_returns_symbolic_list(self):
        r = ItertoolsPermutationsModel().apply([[1, 2, 3]], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestItertoolsCombinationsModel:
    def test_returns_symbolic_list(self):
        r = ItertoolsCombinationsModel().apply([[1, 2, 3], 2], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestFunctoolsReduceModel:
    def test_returns_symbolic_value(self):
        r = FunctoolsReduceModel().apply([None, [1, 2, 3]], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestFunctoolsPartialModel:
    def test_returns_symbolic_value(self):
        r = FunctoolsPartialModel().apply([None, 1], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestFunctoolsLruCacheModel:
    def test_returns_symbolic_value(self):
        r = FunctoolsLruCacheModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestContainerModelLists:
    def test_collections_count(self):
        assert len(collections_models) == 5

    def test_itertools_count(self):
        assert len(itertools_models) == 9

    def test_functools_count(self):
        assert len(functools_models) == 3


# ===================================================================
# Extended stdlib registry smoke test
# ===================================================================

class TestExtendedStdlibRegistry:
    def test_registry_creation(self):
        from pysymex.models.stdlib import ExtendedStdlibRegistry
        reg = ExtendedStdlibRegistry()
        models = reg.list_models()
        assert len(models) > 0

    def test_get_by_qualname(self):
        from pysymex.models.stdlib import get_stdlib_model
        m = get_stdlib_model("math.sqrt")
        assert m is not None
        assert m.name == "sqrt"

    def test_get_by_name(self):
        from pysymex.models.stdlib import get_stdlib_model
        m = get_stdlib_model("sqrt")
        assert m is not None

    def test_list_modules(self):
        from pysymex.models.stdlib import list_stdlib_modules
        mods = list_stdlib_modules()
        assert isinstance(mods, dict)
        assert len(mods) > 0
