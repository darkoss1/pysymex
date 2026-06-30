from __future__ import annotations

import binascii
import bz2
import html
import keyword
import lzma
import marshal
import ntpath
import platform
import posixpath
import pprint
import quopri
import shlex
import stat
import statistics
import struct
import unicodedata

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.stdlib.array.models import ArrayConstructorModel
from pysymex._internal.models.stdlib.binascii.models import (
    BinasciiHexlifyModel,
    BinasciiUnhexlifyModel,
)
from pysymex._internal.models.stdlib.codecs.models import CodecsDecodeModel, CodecsEncodeModel
from pysymex._internal.models.stdlib.copyreg.models import CopyregConstructorModel
from pysymex._internal.models.stdlib.decimal.models import DecimalConstructorModel
from pysymex._internal.models.stdlib.fractions.models import FractionModel
from pysymex._internal.models.stdlib.html.models import HtmlEscapeModel
from pysymex._internal.models.stdlib.keyword.models import KeywordIsKeywordModel
from pysymex._internal.models.stdlib.marshal.models import MarshalDumpsModel, MarshalLoadsModel
from pysymex._internal.models.stdlib.mimetypes.models import MimetypesGuessTypeModel
from pysymex._internal.models.stdlib.ntpath.models import NtPathJoinModel
from pysymex._internal.models.stdlib.numbers.models import NumberConstructorModel
from pysymex._internal.models.stdlib.platform.models import PlatformSystemModel
from pysymex._internal.models.stdlib.posixpath.models import PosixPathJoinModel
from pysymex._internal.models.stdlib.pprint.models import PPrintPformatModel
from pysymex._internal.models.stdlib.registry import get_stdlib_model
from pysymex._internal.models.stdlib.shlex.models import ShlexSplitModel
from pysymex._internal.models.stdlib.stat.models import StatSIsDirModel
from pysymex._internal.models.stdlib.statistics.models import (
    StatisticsMeanModel,
    StatisticsMedianModel,
)
from pysymex._internal.models.stdlib.string.models import StringCapwordsModel
from pysymex._internal.models.stdlib.struct.models import (
    StructCalcsizeModel,
    StructPackModel,
    StructUnpackModel,
)
from pysymex._internal.models.stdlib.textwrap.models import TextwrapDedentModel
from pysymex._internal.models.stdlib.unicodedata.models import UnicodeNormalizeModel


def _state() -> VMState:
    return VMState(pc=7)


def _const_str(value: object) -> str:
    assert isinstance(value, SymbolicString)
    assert z3.is_string_value(value.z3_str)
    return value.z3_str.as_string()


def _const_bytes(value: object) -> bytes:
    assert isinstance(value, SymbolicBytes)
    concrete = value.concrete_value
    assert concrete is not None
    return concrete


def _const_list(value: object) -> list[object]:
    assert isinstance(value, SymbolicList)
    concrete = value.concrete_items
    assert concrete is not None
    return concrete


def _symbolic_value(value: object) -> SymbolicValue:
    assert isinstance(value, SymbolicValue)
    return value


def _registered_model(name: str) -> FunctionModel:
    model = get_stdlib_model(name)
    assert model is not None
    return model


@pytest.mark.parametrize(
    ("qualname", "model_type"),
    [
        ("array.array", ArrayConstructorModel),
        ("binascii.hexlify", BinasciiHexlifyModel),
        ("binascii.unhexlify", BinasciiUnhexlifyModel),
        ("bz2.compress", object),
        ("codecs.encode", CodecsEncodeModel),
        ("copyreg.constructor", CopyregConstructorModel),
        ("decimal.Decimal", DecimalConstructorModel),
        ("fractions.Fraction", FractionModel),
        ("html.escape", HtmlEscapeModel),
        ("keyword.iskeyword", KeywordIsKeywordModel),
        ("lzma.compress", object),
        ("marshal.dumps", MarshalDumpsModel),
        ("mimetypes.guess_type", MimetypesGuessTypeModel),
        ("ntpath.join", NtPathJoinModel),
        ("numbers.Number", NumberConstructorModel),
        ("platform.system", PlatformSystemModel),
        ("posixpath.join", PosixPathJoinModel),
        ("pprint.pformat", PPrintPformatModel),
        ("quopri.encodestring", object),
        ("shlex.split", ShlexSplitModel),
        ("stat.S_ISDIR", StatSIsDirModel),
        ("statistics.mean", StatisticsMeanModel),
        ("struct.calcsize", StructCalcsizeModel),
        ("unicodedata.normalize", UnicodeNormalizeModel),
    ],
)
def test_real_stdlib_family_models_are_registered(qualname: str, model_type: type[object]) -> None:
    assert isinstance(get_stdlib_model(qualname), model_type)


def test_binary_transform_models_match_cpython_for_literals() -> None:
    state = _state()

    assert _const_bytes(BinasciiHexlifyModel().apply([b"az"], {}, state).value) == binascii.hexlify(
        b"az"
    )
    assert _const_bytes(BinasciiUnhexlifyModel().apply(["617a"], {}, state).value) == b"az"
    assert (
        _const_bytes(
            _registered_model("bz2.decompress").apply([bz2.compress(b"x")], {}, state).value
        )
        == b"x"
    )
    assert (
        _const_bytes(
            _registered_model("lzma.decompress").apply([lzma.compress(b"x")], {}, state).value
        )
        == b"x"
    )
    assert (
        _const_bytes(
            _registered_model("quopri.decodestring")
            .apply([quopri.encodestring(b"a b")], {}, state)
            .value
        )
        == b"a b"
    )


def test_codec_and_text_models_match_cpython_for_literals() -> None:
    state = _state()

    assert _const_bytes(CodecsEncodeModel().apply(["cafe", "utf-8"], {}, state).value) == b"cafe"
    assert _const_str(CodecsDecodeModel().apply([b"cafe", "utf-8"], {}, state).value) == "cafe"
    assert _const_str(HtmlEscapeModel().apply(["<x>"], {}, state).value) == html.escape("<x>")
    assert _const_str(StringCapwordsModel().apply(["a b"], {}, state).value) == "A B"
    assert _const_str(TextwrapDedentModel().apply(["  a"], {}, state).value) == "a"
    assert _const_str(
        UnicodeNormalizeModel().apply(["NFC", "e\u0301"], {}, state).value
    ) == unicodedata.normalize("NFC", "e\u0301")


def test_struct_and_marshal_models_preserve_literal_results() -> None:
    state = _state()
    packed = StructPackModel().apply(["!H", 513], {}, state).value

    assert _const_bytes(packed) == struct.pack("!H", 513)
    unpacked = StructUnpackModel().apply(["!H", packed], {}, state).value
    assert isinstance(unpacked, tuple)
    assert isinstance(unpacked[0], SymbolicValue)
    assert unpacked[0].value == 513
    calcsize = _symbolic_value(StructCalcsizeModel().apply(["!H"], {}, state).value)
    assert calcsize.value == struct.calcsize("!H")

    marshalled = MarshalDumpsModel().apply([{"x": 1}], {}, state).value
    assert _const_bytes(marshalled) == marshal.dumps({"x": 1})
    loaded = MarshalLoadsModel().apply([marshalled], {}, state).value
    assert isinstance(loaded, SymbolicValue)
    assert loaded.value == {"x": 1}


def test_statistics_and_token_models_match_cpython_for_literals() -> None:
    state = _state()
    values = [1, 2, 6]
    symbolic_values = SymbolicList.from_const(values)

    mean = _symbolic_value(StatisticsMeanModel().apply([symbolic_values], {}, state).value)
    median = _symbolic_value(StatisticsMedianModel().apply([symbolic_values], {}, state).value)
    is_keyword = _symbolic_value(KeywordIsKeywordModel().apply(["class"], {}, state).value)
    is_dir = _symbolic_value(StatSIsDirModel().apply([stat.S_IFDIR], {}, state).value)

    assert mean.value == statistics.mean(values)
    assert median.value == statistics.median(values)
    assert is_keyword.value == keyword.iskeyword("class")
    assert is_dir.value is True


def test_path_platform_and_shlex_models_match_cpython_for_literals() -> None:
    state = _state()

    assert _const_list(
        ShlexSplitModel().apply(["python -m pysymex"], {}, state).value
    ) == shlex.split("python -m pysymex")
    assert _const_str(NtPathJoinModel().apply(["a", "b"], {}, state).value) == ntpath.join("a", "b")
    assert _const_str(PosixPathJoinModel().apply(["a", "b"], {}, state).value) == posixpath.join(
        "a", "b"
    )
    assert _const_str(PlatformSystemModel().apply([], {}, state).value) == platform.system()
    assert _const_str(PPrintPformatModel().apply([{"x": 1}], {}, state).value) == pprint.pformat(
        {"x": 1}
    )


def test_symbolic_fallbacks_preserve_type_constraints() -> None:
    state = _state()
    symbolic_text, text_constraint = SymbolicString.symbolic("input")

    result = HtmlEscapeModel().apply([symbolic_text], {}, state)

    assert isinstance(result.value, SymbolicString)
    assert result.constraints
    solver = z3.Solver()
    solver.add(text_constraint, *result.constraints)
    assert solver.check() == z3.sat
