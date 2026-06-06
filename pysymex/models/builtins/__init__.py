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

# pyright: reportUnsupportedDunderAll=false

"""Symbolic models for Python builtin functions.

This module provides symbolic handlers for core Python builtins like len,
int, str, etc. It integrates with Z3 to track constraints and side effects.

Implementation spread across four sub-modules:
- ``builtins_base``:  ModelResult dataclass and FunctionModel ABC
- ``builtins_core``:  Core builtin models (len through NoneType)
- ``builtins_extended``:  Extended builtin models (iter through open)
- This file:  ModelRegistry, default_model_registry, and re-exports
"""

from __future__ import annotations

from . import types as _builtin_types
from .base import FunctionModel as FunctionModel, ModelResult as ModelResult
from .exceptions import (
    AssertionErrorModel as AssertionErrorModel,
    AttributeErrorModel as AttributeErrorModel,
    create_exception_models as create_exception_models,
    ExceptionTypeModel as ExceptionTypeModel,
    GeneratorExitModel as GeneratorExitModel,
    IndexErrorModel as IndexErrorModel,
    KeyErrorModel as KeyErrorModel,
    NotImplementedErrorModel as NotImplementedErrorModel,
    RuntimeErrorModel as RuntimeErrorModel,
    StopIterationModel as StopIterationModel,
    TypeErrorModel as TypeErrorModel,
    ValueErrorModel as ValueErrorModel,
    ZeroDivisionErrorModel as ZeroDivisionErrorModel,
)

BuiltinTypeModel = _builtin_types.BuiltinTypeModel
BuiltinBoolModel = _builtin_types.BoolModel
BuiltinBytearrayModel = _builtin_types.BytearrayModel
BuiltinBytesModel = _builtin_types.BytesModel
BuiltinDictModel = _builtin_types.DictModel
BuiltinFloatModel = _builtin_types.FloatModel
BuiltinFrozensetModel = _builtin_types.FrozensetModel
BuiltinIntModel = _builtin_types.IntModel
BuiltinListModel = _builtin_types.ListModel
NoneTypeModel = _builtin_types.NoneTypeModel
BuiltinObjectModel = _builtin_types.ObjectModel
BuiltinSetModel = _builtin_types.SetModel
BuiltinStrModel = _builtin_types.StrModel
BuiltinTupleModel = _builtin_types.TupleModel
TypeModelBase = _builtin_types.TypeModel
TypeModelResult = _builtin_types.TypeModelResult
TypeTypeModel = _builtin_types.TypeTypeModel
from .core.abs import AbsModel as AbsModel
from .core.collections import (
    ListModel as ListModel,
    NoneModel as NoneModel,
    TupleModel as TupleModel,
)
from .core.conversions.numeric import (
    ComplexModel as ComplexModel,
    FloatModel as FloatModel,
    SliceModel as SliceModel,
)
from .core.conversions.scalar import (
    BoolModel as BoolModel,
    IntModel as IntModel,
    StrModel as StrModel,
)
from .core.iterables import (
    EnumerateModel as EnumerateModel,
    FilterModel as FilterModel,
    MapModel as MapModel,
    SortedModel as SortedModel,
    SumModel as SumModel,
    ZipModel as ZipModel,
)
from .core.len import LenModel as LenModel
from .core.max import MaxModel as MaxModel
from .core.min import MinModel as MinModel
from .core.range import RangeModel as RangeModel
from .core.type_checks import (
    IsinstanceModel as IsinstanceModel,
    PrintModel as PrintModel,
    TypeModel as TypeModel,
)
from .extended.attributes import (
    DelattrModel as DelattrModel,
    HasattrModel as HasattrModel,
    SetattrModel as SetattrModel,
)
from .extended.binary_constructors import (
    BytearrayModel as BytearrayModel,
    BytesModel as BytesModel,
    FrozensetModel as FrozensetModel,
    MemoryviewModel as MemoryviewModel,
    ObjectModel as ObjectModel,
)
from .extended.descriptors import (
    AsciiModel as AsciiModel,
    ClassmethodModel as ClassmethodModel,
    DirModel as DirModel,
    PropertyModel as PropertyModel,
    StaticmethodModel as StaticmethodModel,
    VarsModel as VarsModel,
)
from .extended.eval_io import (
    BreakpointModel as BreakpointModel,
    CompileModel as CompileModel,
    EvalModel as EvalModel,
    ExecModel as ExecModel,
    ImportModel as ImportModel,
    InputModel as InputModel,
    OpenModel as OpenModel,
)
from .extended.getattr import GetattrModel as GetattrModel
from .extended.identity import (
    AiterModel as AiterModel,
    AnextModel as AnextModel,
    CallableModel as CallableModel,
    FormatModel as FormatModel,
    HashModel as HashModel,
    IdModel as IdModel,
    ReprModel as ReprModel,
)
from .extended.iterators import (
    IterModel as IterModel,
    NextModel as NextModel,
    ReversedModel as ReversedModel,
)
from .extended.namespace import (
    DictModel as DictModel,
    GlobalsModel as GlobalsModel,
    IssubclassModel as IssubclassModel,
    LocalsModel as LocalsModel,
    SetModel as SetModel,
    SuperModel as SuperModel,
)
from .extended.numeric.format import (
    BinModel as BinModel,
    DivmodModel as DivmodModel,
    HexModel as HexModel,
    OctModel as OctModel,
)
from .extended.numeric.text import (
    ChrModel as ChrModel,
    OrdModel as OrdModel,
    PowModel as PowModel,
    RoundModel as RoundModel,
)
from .extended.truth import AllModel as AllModel, AnyModel as AnyModel
from .extended.terminal import ExitModel as ExitModel, QuitModel as QuitModel
from .extended.interactive_output import (
    CopyrightModel as CopyrightModel,
    CreditsModel as CreditsModel,
    HelpModel as HelpModel,
    LicenseModel as LicenseModel,
)
from .registry import (
    ModelRegistry as ModelRegistry,
    get_default_model_registry,
)


def __getattr__(name: str) -> object:
    """Lazy initialization of default_model_registry to avoid circular imports."""
    if name == "default_model_registry":
        return get_default_model_registry()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


from .builtin.exports import BUILTIN_ALL

__all__ = BUILTIN_ALL
