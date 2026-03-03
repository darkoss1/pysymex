"""Models module for Python builtins and standard library (lazy-loaded).

All public symbols are loaded on first access via ``__getattr__``.
"""

from __future__ import annotations


from importlib import import_module

from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "ASYNCIO_MODELS": ("pysymex.models.asyncio_models", "ASYNCIO_MODELS"),
    "ConditionModel": ("pysymex.models.asyncio_models", "ConditionModel"),
    "CoroutineModel": ("pysymex.models.asyncio_models", "CoroutineModel"),
    "EventModel": ("pysymex.models.asyncio_models", "EventModel"),
    "FutureModel": ("pysymex.models.asyncio_models", "FutureModel"),
    "LockModel": ("pysymex.models.asyncio_models", "LockModel"),
    "QueueModel": ("pysymex.models.asyncio_models", "QueueModel"),
    "SemaphoreModel": ("pysymex.models.asyncio_models", "SemaphoreModel"),
    "TaskModel": ("pysymex.models.asyncio_models", "TaskModel"),
    "get_asyncio_model": ("pysymex.models.asyncio_models", "get_asyncio_model"),
    "AbsModel": ("pysymex.models.builtins", "AbsModel"),
    "BoolModel": ("pysymex.models.builtins", "BoolModel"),
    "FunctionModel": ("pysymex.models.builtins", "FunctionModel"),
    "IntModel": ("pysymex.models.builtins", "IntModel"),
    "LenModel": ("pysymex.models.builtins", "LenModel"),
    "MaxModel": ("pysymex.models.builtins", "MaxModel"),
    "MinModel": ("pysymex.models.builtins", "MinModel"),
    "ModelRegistry": ("pysymex.models.builtins", "ModelRegistry"),
    "ModelResult": ("pysymex.models.builtins", "ModelResult"),
    "PrintModel": ("pysymex.models.builtins", "PrintModel"),
    "RangeModel": ("pysymex.models.builtins", "RangeModel"),
    "StrModel": ("pysymex.models.builtins", "StrModel"),
    "default_model_registry": ("pysymex.models.builtins", "default_model_registry"),
    "CONTEXTLIB_MODELS": ("pysymex.models.contextlib_models", "CONTEXTLIB_MODELS"),
    "AsyncContextManagerModel": ("pysymex.models.contextlib_models", "AsyncContextManagerModel"),
    "AsyncExitStackModel": ("pysymex.models.contextlib_models", "AsyncExitStackModel"),
    "ContextDecoratorModel": ("pysymex.models.contextlib_models", "ContextDecoratorModel"),
    "ContextManagerModel": ("pysymex.models.contextlib_models", "ContextManagerModel"),
    "ExitStackModel": ("pysymex.models.contextlib_models", "ExitStackModel"),
    "get_contextlib_model": ("pysymex.models.contextlib_models", "get_contextlib_model"),
    "DATACLASSES_MODELS": ("pysymex.models.dataclasses_models", "DATACLASSES_MODELS"),
    "FieldInfo": ("pysymex.models.dataclasses_models", "FieldInfo"),
    "asdict_model": ("pysymex.models.dataclasses_models", "asdict_model"),
    "astuple_model": ("pysymex.models.dataclasses_models", "astuple_model"),
    "dataclass_model": ("pysymex.models.dataclasses_models", "dataclass_model"),
    "field_model": ("pysymex.models.dataclasses_models", "field_model"),
    "fields_model": ("pysymex.models.dataclasses_models", "fields_model"),
    "get_dataclasses_model": ("pysymex.models.dataclasses_models", "get_dataclasses_model"),
    "is_dataclass_model": ("pysymex.models.dataclasses_models", "is_dataclass_model"),
    "make_dataclass_model": ("pysymex.models.dataclasses_models", "make_dataclass_model"),
    "replace_model": ("pysymex.models.dataclasses_models", "replace_model"),
    "DICT_MODELS": ("pysymex.models.dicts", "DICT_MODELS"),
    "DictGetModel": ("pysymex.models.dicts", "DictGetModel"),
    "DictItemsModel": ("pysymex.models.dicts", "DictItemsModel"),
    "DictKeysModel": ("pysymex.models.dicts", "DictKeysModel"),
    "DictValuesModel": ("pysymex.models.dicts", "DictValuesModel"),
    "LIST_MODELS": ("pysymex.models.lists", "LIST_MODELS"),
    "ListAppendModel": ("pysymex.models.lists", "ListAppendModel"),
    "ListExtendModel": ("pysymex.models.lists", "ListExtendModel"),
    "ListInsertModel": ("pysymex.models.lists", "ListInsertModel"),
    "ListPopModel": ("pysymex.models.lists", "ListPopModel"),
    "BoundMethod": ("pysymex.models.objects", "BoundMethod"),
    "ClassRegistry": ("pysymex.models.objects", "ClassRegistry"),
    "MethodType": ("pysymex.models.objects", "MethodType"),
    "SymbolicAttribute": ("pysymex.models.objects", "SymbolicAttribute"),
    "SymbolicClass": ("pysymex.models.objects", "SymbolicClass"),
    "SymbolicDescriptor": ("pysymex.models.objects", "SymbolicDescriptor"),
    "SymbolicInstance": ("pysymex.models.objects", "SymbolicInstance"),
    "SymbolicMethod": ("pysymex.models.objects", "SymbolicMethod"),
    "SymbolicProperty": ("pysymex.models.objects", "SymbolicProperty"),
    "TypeChecker": ("pysymex.models.objects", "TypeChecker"),
    "REGEX_MODELS": ("pysymex.models.regex", "REGEX_MODELS"),
    "PatternCompiler": ("pysymex.models.regex", "PatternCompiler"),
    "ReCompileModel": ("pysymex.models.regex", "ReCompileModel"),
    "ReEscapeModel": ("pysymex.models.regex", "ReEscapeModel"),
    "ReFullmatchModel": ("pysymex.models.regex", "ReFullmatchModel"),
    "ReSplitModel": ("pysymex.models.regex", "ReSplitModel"),
    "ReSubModel": ("pysymex.models.regex", "ReSubModel"),
    "compile_pattern": ("pysymex.models.regex", "compile_pattern"),
    "EnhancedReFindallModel": ("pysymex.models.regex", "ReFindallModel"),
    "EnhancedReMatchModel": ("pysymex.models.regex", "ReMatchModel"),
    "EnhancedReSearchModel": ("pysymex.models.regex", "ReSearchModel"),
    "SET_MODELS": ("pysymex.models.sets", "SET_MODELS"),
    "SetAddModel": ("pysymex.models.sets", "SetAddModel"),
    "SetClearModel": ("pysymex.models.sets", "SetClearModel"),
    "SetContainsModel": ("pysymex.models.sets", "SetContainsModel"),
    "SetCopyModel": ("pysymex.models.sets", "SetCopyModel"),
    "SetDiscardModel": ("pysymex.models.sets", "SetDiscardModel"),
    "SetIntersectionModel": ("pysymex.models.sets", "SetIntersectionModel"),
    "SetLenModel": ("pysymex.models.sets", "SetLenModel"),
    "SetPopModel": ("pysymex.models.sets", "SetPopModel"),
    "SetRemoveModel": ("pysymex.models.sets", "SetRemoveModel"),
    "SetUnionModel": ("pysymex.models.sets", "SetUnionModel"),
    "CounterModel": ("pysymex.models.stdlib", "CounterModel"),
    "DefaultdictModel": ("pysymex.models.stdlib", "DefaultdictModel"),
    "DequeModel": ("pysymex.models.stdlib", "DequeModel"),
    "ExtendedStdlibRegistry": ("pysymex.models.stdlib", "ExtendedStdlibRegistry"),
    "ItertoolsChainModel": ("pysymex.models.stdlib", "ItertoolsChainModel"),
    "ItertoolsIsliceModel": ("pysymex.models.stdlib", "ItertoolsIsliceModel"),
    "ItertoolsProductModel": ("pysymex.models.stdlib", "ItertoolsProductModel"),
    "JsonDumpsModel": ("pysymex.models.stdlib", "JsonDumpsModel"),
    "JsonLoadsModel": ("pysymex.models.stdlib", "JsonLoadsModel"),
    "MathCeilModel": ("pysymex.models.stdlib", "MathCeilModel"),
    "MathCosModel": ("pysymex.models.stdlib", "MathCosModel"),
    "MathExpModel": ("pysymex.models.stdlib", "MathExpModel"),
    "MathFloorModel": ("pysymex.models.stdlib", "MathFloorModel"),
    "MathLogModel": ("pysymex.models.stdlib", "MathLogModel"),
    "MathSinModel": ("pysymex.models.stdlib", "MathSinModel"),
    "MathSqrtModel": ("pysymex.models.stdlib", "MathSqrtModel"),
    "OrderedDictModel": ("pysymex.models.stdlib", "OrderedDictModel"),
    "RandomChoiceModel": ("pysymex.models.stdlib", "RandomChoiceModel"),
    "RandomRandintModel": ("pysymex.models.stdlib", "RandomRandintModel"),
    "ReFindallModel": ("pysymex.models.stdlib", "ReFindallModel"),
    "ReMatchModel": ("pysymex.models.stdlib", "ReMatchModel"),
    "ReSearchModel": ("pysymex.models.stdlib", "ReSearchModel"),
    "extended_stdlib_registry": ("pysymex.models.stdlib", "extended_stdlib_registry"),
    "get_stdlib_model": ("pysymex.models.stdlib", "get_stdlib_model"),
    "list_stdlib_models": ("pysymex.models.stdlib", "list_stdlib_models"),
    "list_stdlib_modules": ("pysymex.models.stdlib", "list_stdlib_modules"),
    "STRING_MODELS": ("pysymex.models.strings", "STRING_MODELS"),
    "StrJoinModel": ("pysymex.models.strings", "StrJoinModel"),
    "StrLowerModel": ("pysymex.models.strings", "StrLowerModel"),
    "StrReplaceModel": ("pysymex.models.strings", "StrReplaceModel"),
    "StrSplitModel": ("pysymex.models.strings", "StrSplitModel"),
    "StrStripModel": ("pysymex.models.strings", "StrStripModel"),
    "StrUpperModel": ("pysymex.models.strings", "StrUpperModel"),
    "THREADING_MODELS": ("pysymex.models.threading_models", "THREADING_MODELS"),
    "BarrierModel": ("pysymex.models.threading_models", "BarrierModel"),
    "ThreadingConditionModel": ("pysymex.models.threading_models", "ConditionModel"),
    "ThreadingEventModel": ("pysymex.models.threading_models", "EventModel"),
    "ThreadingLockModel": ("pysymex.models.threading_models", "LockModel"),
    "RLockModel": ("pysymex.models.threading_models", "RLockModel"),
    "ThreadingSemaphoreModel": ("pysymex.models.threading_models", "SemaphoreModel"),
    "ThreadModel": ("pysymex.models.threading_models", "ThreadModel"),
    "get_threading_model": ("pysymex.models.threading_models", "get_threading_model"),
    "COLLECTIONS_MODELS": ("pysymex.models.collections_models", "COLLECTIONS_MODELS"),
    "ChainMapModel": ("pysymex.models.collections_models", "ChainMapModel"),
    "EnhancedCounterModel": ("pysymex.models.collections_models", "CounterModel"),
    "DefaultDictModel": ("pysymex.models.collections_models", "DefaultDictModel"),
    "EnhancedDequeModel": ("pysymex.models.collections_models", "DequeModel"),
    "EnhancedOrderedDictModel": ("pysymex.models.collections_models", "OrderedDictModel"),
    "get_collections_model": ("pysymex.models.collections_models", "get_collections_model"),
    "register_collections_models": (
        "pysymex.models.collections_models",
        "register_collections_models",
    ),
    "ITERTOOLS_MODELS": ("pysymex.models.itertools_models", "ITERTOOLS_MODELS"),
    "get_itertools_model": ("pysymex.models.itertools_models", "get_itertools_model"),
    "register_itertools_models": ("pysymex.models.itertools_models", "register_itertools_models"),
    "FUNCTOOLS_MODELS": ("pysymex.models.functools_models", "FUNCTOOLS_MODELS"),
    "PartialModel": ("pysymex.models.functools_models", "PartialModel"),
    "get_functools_model": ("pysymex.models.functools_models", "get_functools_model"),
    "register_functools_models": ("pysymex.models.functools_models", "register_functools_models"),
    "PATHLIB_MODELS": ("pysymex.models.pathlib_models", "PATHLIB_MODELS"),
}


__all__ = sorted(_EXPORTS.keys())


def __getattr__(name: str) -> Any:
    """Lazy-load model exports to prevent eager side-effect imports."""

    target = _EXPORTS.get(name)

    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

    module_name, attr_name = target

    module = import_module(module_name)

    value = getattr(module, attr_name)

    globals()[name] = value

    return value


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(globals()))
