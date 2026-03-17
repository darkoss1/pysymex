"""Tests for extended builtin function models (builtins_extended.py).

Phase 2 -- covers iter, next, super, issubclass, globals, locals, dict, set,
reversed, all, any, ord, chr, pow, round, divmod, hasattr, getattr, setattr,
id, hash, callable, repr, format, input, open, exec, eval, compile, bin, oct,
hex, bytes, bytearray, frozenset, memoryview, object, property, classmethod,
staticmethod, vars, dir, ascii, breakpoint.
"""

from __future__ import annotations

import pytest
import z3

from tests.helpers import make_state, make_symbolic_int, make_symbolic_str, solve
from pysymex.core.types import (
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.models.builtins_base import ModelResult
from pysymex.models.builtins_extended import (
    IterModel,
    NextModel,
    SuperModel,
    IssubclassModel,
    GlobalsModel,
    LocalsModel,
    DictModel,
    SetModel,
    ReversedModel,
    AllModel,
    AnyModel,
    OrdModel,
    ChrModel,
    PowModel,
    RoundModel,
    DivmodModel,
    HasattrModel,
    GetattrModel,
    SetattrModel,
    IdModel,
    HashModel,
    CallableModel,
    ReprModel,
    FormatModel,
    InputModel,
    OpenModel,
    ExecModel,
    EvalModel,
    CompileModel,
    BinModel,
    OctModel,
    HexModel,
    BytesModel,
    BytearrayModel,
    FrozensetModel,
    MemoryviewModel,
    ObjectModel,
    PropertyModel,
    ClassmethodModel,
    StaticmethodModel,
    VarsModel,
    DirModel,
    AsciiModel,
    BreakpointModel,
)


def _state(pc=0):
    return make_state(pc=pc)


class TestIterModel:
    def test_qualname(self):
        assert IterModel().qualname == "builtins.iter"

    def test_no_args(self):
        r = IterModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_list_passthrough(self):
        r = IterModel().apply([[1, 2]], {}, _state())
        assert r.value == [1, 2]

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("l")
        r = IterModel().apply([sl], {}, _state())
        assert r.value is sl


class TestNextModel:
    def test_qualname(self):
        assert NextModel().qualname == "builtins.next"

    def test_returns_symbolic(self):
        r = NextModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestSuperModel:
    def test_qualname(self):
        assert SuperModel().qualname == "builtins.super"

    def test_returns_symbolic(self):
        r = SuperModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestIssubclassModel:
    def test_qualname(self):
        assert IssubclassModel().qualname == "builtins.issubclass"

    def test_returns_symbolic_bool(self):
        r = IssubclassModel().apply([int, object], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 2


class TestGlobalsModel:
    def test_qualname(self):
        assert GlobalsModel().qualname == "builtins.globals"

    def test_returns_result(self):
        r = GlobalsModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestLocalsModel:
    def test_qualname(self):
        assert LocalsModel().qualname == "builtins.locals"

    def test_returns_result(self):
        r = LocalsModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestDictModel:
    def test_qualname(self):
        assert DictModel().qualname == "builtins.dict"

    def test_no_args(self):
        r = DictModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

    def test_with_kwargs(self):
        r = DictModel().apply([], {"a": 1}, _state())
        assert isinstance(r, ModelResult)


class TestSetModel:
    def test_qualname(self):
        assert SetModel().qualname == "builtins.set"

    def test_no_args(self):
        r = SetModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_list(self):
        r = SetModel().apply([[1, 2, 2]], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestReversedModel:
    def test_qualname(self):
        assert ReversedModel().qualname == "builtins.reversed"

    def test_no_args(self):
        r = ReversedModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)

    def test_symbolic_list(self):
        sl, _ = SymbolicList.symbolic("lst")
        r = ReversedModel().apply([sl], {}, _state())
        assert isinstance(r.value, SymbolicList)
        assert len(r.constraints) >= 2

    def test_concrete_list(self):
        r = ReversedModel().apply([[3, 1, 2]], {}, _state())
        assert r.value == [2, 1, 3]


class TestAllModel:
    def test_qualname(self):
        assert AllModel().qualname == "builtins.all"

    def test_no_args(self):
        r = AllModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

    def test_empty_list(self):
        r = AllModel().apply([[]], {}, _state())
        assert isinstance(r, ModelResult)

    def test_concrete_true(self):
        r = AllModel().apply([[1, 2, 3]], {}, _state())
        assert isinstance(r, ModelResult)


class TestAnyModel:
    def test_qualname(self):
        assert AnyModel().qualname == "builtins.any"

    def test_no_args(self):
        r = AnyModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)

    def test_empty_list(self):
        r = AnyModel().apply([[]], {}, _state())
        assert isinstance(r, ModelResult)


class TestOrdModel:
    def test_qualname(self):
        assert OrdModel().qualname == "builtins.ord"

    def test_no_args(self):
        r = OrdModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_char(self):
        r = OrdModel().apply(["A"], {}, _state())
        assert isinstance(r, ModelResult)

    def test_symbolic_string(self):
        ss = make_symbolic_str("c")
        r = OrdModel().apply([ss], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 4


class TestChrModel:
    def test_qualname(self):
        assert ChrModel().qualname == "builtins.chr"

    def test_no_args(self):
        r = ChrModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_concrete_int(self):
        r = ChrModel().apply([65], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_symbolic_int(self):
        sv = make_symbolic_int("x")
        r = ChrModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicString)
        assert len(r.constraints) >= 4


class TestPowModel:
    def test_qualname(self):
        assert PowModel().qualname == "builtins.pow"

    def test_no_args(self):
        r = PowModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete(self):
        r = PowModel().apply([2, 10], {}, _state())
        assert isinstance(r, ModelResult)

    def test_concrete_with_mod(self):
        r = PowModel().apply([2, 10, 100], {}, _state())
        assert isinstance(r, ModelResult)


class TestRoundModel:
    def test_qualname(self):
        assert RoundModel().qualname == "builtins.round"

    def test_no_args(self):
        r = RoundModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_int(self):
        r = RoundModel().apply([3], {}, _state())
        assert r.value == 3

    def test_concrete_float(self):
        r = RoundModel().apply([3.7], {}, _state())
        assert r.value == 4


class TestDivmodModel:
    def test_qualname(self):
        assert DivmodModel().qualname == "builtins.divmod"

    def test_no_args(self):
        r = DivmodModel().apply([], {}, _state())
        assert isinstance(r.value, tuple)

    def test_concrete(self):
        r = DivmodModel().apply([7, 3], {}, _state())
        assert isinstance(r.value, tuple)
        assert len(r.value) == 2

    def test_symbolic(self):
        a = make_symbolic_int("a")
        b = make_symbolic_int("b")
        r = DivmodModel().apply([a, b], {}, _state())
        assert isinstance(r.value, tuple)
        assert len(r.constraints) >= 6


class TestHasattrModel:
    def test_qualname(self):
        assert HasattrModel().qualname == "builtins.hasattr"

    def test_no_args(self):
        r = HasattrModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_obj(self):
        r = HasattrModel().apply(["hello", "upper"], {}, _state())
        assert isinstance(r, ModelResult)


class TestGetattrModel:
    def test_qualname(self):
        assert GetattrModel().qualname == "builtins.getattr"

    def test_no_args(self):
        r = GetattrModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_obj(self):
        r = GetattrModel().apply(["hello", "upper"], {}, _state())
        assert isinstance(r, ModelResult)


class TestSetattrModel:
    def test_qualname(self):
        assert SetattrModel().qualname == "builtins.setattr"

    def test_returns_none(self):
        r = SetattrModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("mutates_arg") == 0


class TestIdModel:
    def test_qualname(self):
        assert IdModel().qualname == "builtins.id"

    def test_no_args(self):
        r = IdModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_with_arg(self):
        r = IdModel().apply([42], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert len(r.constraints) >= 3


class TestHashModel:
    def test_qualname(self):
        assert HashModel().qualname == "builtins.hash"

    def test_no_args(self):
        r = HashModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_int(self):
        r = HashModel().apply([42], {}, _state())
        assert isinstance(r, ModelResult)

    def test_concrete_string(self):
        r = HashModel().apply(["hello"], {}, _state())
        assert isinstance(r, ModelResult)


class TestCallableModel:
    def test_qualname(self):
        assert CallableModel().qualname == "builtins.callable"

    def test_no_args(self):
        r = CallableModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)

    def test_concrete_callable(self):
        r = CallableModel().apply([len], {}, _state())
        assert isinstance(r, ModelResult)


class TestReprModel:
    def test_qualname(self):
        assert ReprModel().qualname == "builtins.repr"

    def test_no_args(self):
        r = ReprModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_concrete(self):
        r = ReprModel().apply([42], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestFormatModel:
    def test_qualname(self):
        assert FormatModel().qualname == "builtins.format"

    def test_no_args(self):
        r = FormatModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_concrete(self):
        r = FormatModel().apply([42, "d"], {}, _state())
        assert isinstance(r.value, SymbolicString)


class TestInputModel:
    def test_qualname(self):
        assert InputModel().qualname == "builtins.input"

    def test_returns_string_with_io(self):
        r = InputModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicString)
        assert r.side_effects.get("io") is True


class TestOpenModel:
    def test_qualname(self):
        assert OpenModel().qualname == "builtins.open"

    def test_returns_value_with_io(self):
        r = OpenModel().apply(["file.txt"], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert r.side_effects.get("io") is True


class TestExecModel:
    def test_qualname(self):
        assert ExecModel().qualname == "builtins.exec"

    def test_returns_none(self):
        r = ExecModel().apply(["pass"], {}, _state())
        assert isinstance(r.value, SymbolicNone)
        assert r.side_effects.get("code_injection") is True

    def test_tainted_symbolic(self):
        ss = make_symbolic_str("code")
        r = ExecModel().apply([ss], {}, _state())
        assert r.side_effects.get("tainted_input") is True
        assert r.side_effects.get("severity") == "critical"


class TestEvalModel:
    def test_qualname(self):
        assert EvalModel().qualname == "builtins.eval"

    def test_returns_symbolic(self):
        r = EvalModel().apply(["1+1"], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert r.side_effects.get("code_injection") is True

    def test_tainted_symbolic(self):
        ss = make_symbolic_str("expr")
        r = EvalModel().apply([ss], {}, _state())
        assert r.side_effects.get("tainted_input") is True


class TestCompileModel:
    def test_qualname(self):
        assert CompileModel().qualname == "builtins.compile"

    def test_returns_symbolic(self):
        r = CompileModel().apply(["pass", "<string>", "exec"], {}, _state())
        assert isinstance(r.value, SymbolicValue)
        assert r.side_effects.get("code_injection") is True


class TestBinModel:
    def test_qualname(self):
        assert BinModel().qualname == "builtins.bin"

    def test_returns_string(self):
        r = BinModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicString)

    def test_with_symbolic_int(self):
        sv = make_symbolic_int("x")
        r = BinModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicString)
        assert len(r.constraints) >= 2


class TestOctModel:
    def test_qualname(self):
        assert OctModel().qualname == "builtins.oct"

    def test_returns_string(self):
        sv = make_symbolic_int("x")
        r = OctModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicString)
        assert len(r.constraints) >= 2


class TestHexModel:
    def test_qualname(self):
        assert HexModel().qualname == "builtins.hex"

    def test_returns_string(self):
        sv = make_symbolic_int("x")
        r = HexModel().apply([sv], {}, _state())
        assert isinstance(r.value, SymbolicString)
        assert len(r.constraints) >= 2


class TestBytesModel:
    def test_qualname(self):
        assert BytesModel().qualname == "builtins.bytes"

    def test_no_args(self):
        r = BytesModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestBytearrayModel:
    def test_qualname(self):
        assert BytearrayModel().qualname == "builtins.bytearray"

    def test_no_args(self):
        r = BytearrayModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicList)


class TestFrozensetModel:
    def test_qualname(self):
        assert FrozensetModel().qualname == "builtins.frozenset"

    def test_no_args(self):
        r = FrozensetModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestMemoryviewModel:
    def test_qualname(self):
        assert MemoryviewModel().qualname == "builtins.memoryview"

    def test_returns_symbolic(self):
        r = MemoryviewModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestObjectModel:
    def test_qualname(self):
        assert ObjectModel().qualname == "builtins.object"

    def test_returns_symbolic(self):
        r = ObjectModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestPropertyModel:
    def test_qualname(self):
        assert PropertyModel().qualname == "builtins.property"

    def test_returns_symbolic(self):
        r = PropertyModel().apply([], {}, _state())
        assert isinstance(r.value, SymbolicValue)


class TestClassmethodModel:
    def test_qualname(self):
        assert ClassmethodModel().qualname == "builtins.classmethod"

    def test_returns_symbolic(self):
        r = ClassmethodModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestStaticmethodModel:
    def test_qualname(self):
        assert StaticmethodModel().qualname == "builtins.staticmethod"

    def test_returns_symbolic(self):
        r = StaticmethodModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestVarsModel:
    def test_qualname(self):
        assert VarsModel().qualname == "builtins.vars"

    def test_returns_result(self):
        r = VarsModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestDirModel:
    def test_qualname(self):
        assert DirModel().qualname == "builtins.dir"

    def test_returns_result(self):
        r = DirModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestAsciiModel:
    def test_qualname(self):
        assert AsciiModel().qualname == "builtins.ascii"

    def test_returns_result(self):
        r = AsciiModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)


class TestBreakpointModel:
    def test_qualname(self):
        assert BreakpointModel().qualname == "builtins.breakpoint"

    def test_returns_none(self):
        r = BreakpointModel().apply([], {}, _state())
        assert isinstance(r, ModelResult)
