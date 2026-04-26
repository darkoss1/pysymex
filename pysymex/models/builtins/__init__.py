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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


from .base import FunctionModel, ModelResult
from .exceptions import (
    AssertionErrorModel,
    AttributeErrorModel,
    create_exception_models,
    ExceptionTypeModel,
    GeneratorExitModel,
    IndexErrorModel,
    KeyErrorModel,
    NotImplementedErrorModel,
    RuntimeErrorModel,
    StopIterationModel,
    TypeErrorModel,
    ValueErrorModel,
    ZeroDivisionErrorModel,
)
from .types import (
    BuiltinTypeModel,
    BoolModel as BuiltinBoolModel,
    BytearrayModel as BuiltinBytearrayModel,
    BytesModel as BuiltinBytesModel,
    DictModel as BuiltinDictModel,
    FloatModel as BuiltinFloatModel,
    FrozensetModel as BuiltinFrozensetModel,
    IntModel as BuiltinIntModel,
    ListModel as BuiltinListModel,
    NoneTypeModel,
    ObjectModel as BuiltinObjectModel,
    SetModel as BuiltinSetModel,
    StrModel as BuiltinStrModel,
    TupleModel as BuiltinTupleModel,
    TypeModel as TypeModelBase,
    TypeModelResult,
    TypeTypeModel,
)
from .core import (
    AbsModel,
    BoolModel,
    EnumerateModel,
    FilterModel,
    FloatModel,
    IntModel,
    IsinstanceModel,
    LenModel,
    ListModel,
    MapModel,
    MaxModel,
    MinModel,
    NoneModel,
    PrintModel,
    RangeModel,
    SortedModel,
    StrModel,
    SumModel,
    TupleModel,
    TypeModel,
    ZipModel,
)
from .extended import (
    AllModel,
    AnyModel,
    AsciiModel,
    BinModel,
    BreakpointModel,
    BytearrayModel,
    BytesModel,
    CallableModel,
    ChrModel,
    ClassmethodModel,
    CompileModel,
    DictModel,
    DirModel,
    DivmodModel,
    EvalModel,
    ExecModel,
    FormatModel,
    FrozensetModel,
    GetattrModel,
    GlobalsModel,
    HasattrModel,
    HashModel,
    HexModel,
    IdModel,
    InputModel,
    IssubclassModel,
    IterModel,
    LocalsModel,
    MemoryviewModel,
    NextModel,
    ObjectModel,
    OctModel,
    OpenModel,
    OrdModel,
    PowModel,
    PropertyModel,
    ReprModel,
    ReversedModel,
    RoundModel,
    SetattrModel,
    SetModel,
    StaticmethodModel,
    SuperModel,
    VarsModel,
)

_TYPE_AND_EXCEPTION_EXPORTS: dict[str, object] = {
    "AssertionErrorModel": AssertionErrorModel,
    "AttributeErrorModel": AttributeErrorModel,
    "create_exception_models": create_exception_models,
    "ExceptionTypeModel": ExceptionTypeModel,
    "GeneratorExitModel": GeneratorExitModel,
    "IndexErrorModel": IndexErrorModel,
    "KeyErrorModel": KeyErrorModel,
    "NotImplementedErrorModel": NotImplementedErrorModel,
    "RuntimeErrorModel": RuntimeErrorModel,
    "StopIterationModel": StopIterationModel,
    "TypeErrorModel": TypeErrorModel,
    "ValueErrorModel": ValueErrorModel,
    "ZeroDivisionErrorModel": ZeroDivisionErrorModel,
    "BuiltinTypeModel": BuiltinTypeModel,
    "BuiltinBoolModel": BuiltinBoolModel,
    "BuiltinBytearrayModel": BuiltinBytearrayModel,
    "BuiltinBytesModel": BuiltinBytesModel,
    "BuiltinDictModel": BuiltinDictModel,
    "BuiltinFloatModel": BuiltinFloatModel,
    "BuiltinFrozensetModel": BuiltinFrozensetModel,
    "BuiltinIntModel": BuiltinIntModel,
    "BuiltinListModel": BuiltinListModel,
    "NoneTypeModel": NoneTypeModel,
    "BuiltinObjectModel": BuiltinObjectModel,
    "BuiltinSetModel": BuiltinSetModel,
    "BuiltinStrModel": BuiltinStrModel,
    "BuiltinTupleModel": BuiltinTupleModel,
    "TypeModelBase": TypeModelBase,
    "TypeModelResult": TypeModelResult,
    "TypeTypeModel": TypeTypeModel,
}


class ModelRegistry:
    """Registry for function models."""

    def __init__(self) -> None:
        """Initialize a new ModelRegistry instance."""
        self._models: dict[str, FunctionModel] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register default builtin models and standard library models."""
        from pysymex.models.builtins.core import ComplexModel, SliceModel
        from pysymex.models.builtins.extended import EXTENDED_MODELS
        from pysymex.models.containers.bytes import BYTES_MODELS
        from pysymex.models.containers.dicts import DICT_MODELS
        from pysymex.models.containers.frozensets import FROZENSET_MODELS
        from pysymex.models.containers.lists import LIST_MODELS
        from pysymex.models.numeric import INT_FLOAT_MODELS
        from pysymex.models.containers.sets import SET_MODELS
        from pysymex.models.stdlib import (
            bisect_models,
            collections_models,
            copy_models,
            dataclasses_models,
            datetime_models,
            enum_models,
            functools_models,
            heapq_models,
            io_models,
            itertools_models,
            json_models,
            math_models,
            operator_models,
            ospath_models,
            random_models,
            re_models,
            types_models,
        )
        from pysymex.models.containers.strings import STRING_MODELS
        from pysymex.models.containers.tuples import TUPLE_MODELS

        all_models = [
            IntModel(),
            FloatModel(),
            BoolModel(),
            StrModel(),
            ListModel(),
            DictModel(),
            TupleModel(),
            NoneModel(),
            TypeModel(),
            PrintModel(),
            AbsModel(),
            MinModel(),
            MaxModel(),
            SumModel(),
            AnyModel(),
            AllModel(),
            ZipModel(),
            RangeModel(),
            EnumerateModel(),
            FilterModel(),
            MapModel(),
            IterModel(),
            NextModel(),
            SuperModel(),
            GetattrModel(),
            SetattrModel(),
            HasattrModel(),
            IsinstanceModel(),
            IssubclassModel(),
            IdModel(),
            HashModel(),
            GlobalsModel(),
            LocalsModel(),
            LenModel(),
            SetModel(),
            SortedModel(),
            ReversedModel(),
            PowModel(),
            RoundModel(),
            DivmodModel(),
            CallableModel(),
            OrdModel(),
            ChrModel(),
            ReprModel(),
            FormatModel(),
            InputModel(),
            OpenModel(),
            ExecModel(),
            EvalModel(),
            CompileModel(),
            BinModel(),
            OctModel(),
            HexModel(),
            BytesModel(),
            BytearrayModel(),
            FrozensetModel(),
            MemoryviewModel(),
            ObjectModel(),
            PropertyModel(),
            ClassmethodModel(),
            StaticmethodModel(),
            VarsModel(),
            DirModel(),
            AsciiModel(),
            BreakpointModel(),
            ComplexModel(),
            SliceModel(),
            *math_models,
            *collections_models,
            *itertools_models,
            *functools_models,
            *ospath_models,
            *json_models,
            *re_models,
            *random_models,
            *datetime_models,
            *types_models,
            *operator_models,
            *copy_models,
            *io_models,
            *heapq_models,
            *bisect_models,
            *enum_models,
            *dataclasses_models,
            *DICT_MODELS,
            *LIST_MODELS,
            *STRING_MODELS,
            *EXTENDED_MODELS,
            *SET_MODELS,
            *TUPLE_MODELS,
            *BYTES_MODELS,
            *FROZENSET_MODELS,
            *INT_FLOAT_MODELS,
        ]
        for model in all_models:
            self.register(model)

    def register(self, model: FunctionModel) -> None:
        """Register a function model."""
        self._models[model.name] = model
        if model.qualname != model.name:
            self._models[model.qualname] = model

    def get(self, name: str) -> FunctionModel | None:
        """Get a model by name."""
        return self._models.get(name)

    def apply(
        self,
        func: object,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult | None:
        """Try to apply a model for a function."""
        func_name = getattr(func, "__name__", None)
        if isinstance(func_name, str):
            model = self.get(func_name)
            if model:
                return model.apply(args, kwargs, state)
        model = self.get(str(func))
        if model:
            return model.apply(args, kwargs, state)
        return None

    def has_model(self, func: object) -> bool:
        """Check if a model exists for a function."""
        func_name = getattr(func, "__name__", None)
        if isinstance(func_name, str):
            return func_name in self._models
        return str(func) in self._models

    def list_models(self) -> list[str]:
        """List all registered model names."""
        return list({m.name for m in self._models.values()})


default_model_registry = ModelRegistry()
