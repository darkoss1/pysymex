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


from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from .builtins_base import FunctionModel, ModelResult


from .builtins_core import (
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


from .builtins_extended import (
    AllModel,
    AnyModel,
    CallableModel,
    ChrModel,
    DictModel,
    DivmodModel,
    FormatModel,
    GetattrModel,
    GlobalsModel,
    HasattrModel,
    HashModel,
    IdModel,
    InputModel,
    IssubclassModel,
    IterModel,
    LocalsModel,
    NextModel,
    OpenModel,
    OrdModel,
    PowModel,
    ReprModel,
    ReversedModel,
    RoundModel,
    SetattrModel,
    SetModel,
    SuperModel,
)


class ModelRegistry:
    """Registry for function models."""

    def __init__(self):
        self._models: dict[str, FunctionModel] = {}

        self._register_defaults()

    def _register_defaults(self):
        """Register default builtin models and standard library models."""

        from pysymex.models.dicts import DICT_MODELS

        from pysymex.models.lists import LIST_MODELS

        from pysymex.models.sets import SET_MODELS

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

        from pysymex.models.strings import STRING_MODELS

        all_models = (
            [
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
            ]
            + math_models
            + collections_models
            + itertools_models
            + functools_models
            + ospath_models
            + json_models
            + re_models
            + random_models
            + datetime_models
            + types_models
            + operator_models
            + copy_models
            + io_models
            + heapq_models
            + bisect_models
            + enum_models
            + dataclasses_models
            + DICT_MODELS
            + LIST_MODELS
            + STRING_MODELS
            + SET_MODELS
        )

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
        func: Any,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult | None:
        """Try to apply a model for a function."""

        if hasattr(func, "__name__"):
            model = self.get(func.__name__)

            if model:
                return model.apply(args, kwargs, state)

        model = self.get(str(func))

        if model:
            return model.apply(args, kwargs, state)

        return None

    def has_model(self, func: Any) -> bool:
        """Check if a model exists for a function."""

        if hasattr(func, "__name__"):
            return func.__name__ in self._models

        return str(func) in self._models

    def list_models(self) -> list[str]:
        """List all registered model names."""

        return list({m.name for m in self._models.values()})


default_model_registry = ModelRegistry()
