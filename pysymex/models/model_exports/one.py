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

from __future__ import annotations

MODEL_EXPORTS_1 = {
    "ASYNCIO_MODELS": ("pysymex.models.concurrency.asyncio", "ASYNCIO_MODELS"),
    "ConditionModel": ("pysymex.models.concurrency.asyncio", "ConditionModel"),
    "CoroutineModel": ("pysymex.models.concurrency.asyncio", "CoroutineModel"),
    "EventModel": ("pysymex.models.concurrency.asyncio", "EventModel"),
    "FutureModel": ("pysymex.models.concurrency.asyncio", "FutureModel"),
    "LockModel": ("pysymex.models.concurrency.asyncio", "LockModel"),
    "QueueModel": ("pysymex.models.concurrency.asyncio", "QueueModel"),
    "SemaphoreModel": ("pysymex.models.concurrency.asyncio", "SemaphoreModel"),
    "TaskModel": ("pysymex.models.concurrency.asyncio", "TaskModel"),
    "get_asyncio_model": ("pysymex.models.concurrency.asyncio", "get_asyncio_model"),
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
    "CONTEXTLIB_MODELS": ("pysymex.models.stdlib.contextlib", "CONTEXTLIB_MODELS"),
    "AsyncContextManagerModel": ("pysymex.models.stdlib.contextlib", "AsyncContextManagerModel"),
    "AsyncExitStackModel": ("pysymex.models.stdlib.contextlib", "AsyncExitStackModel"),
    "ContextDecoratorModel": ("pysymex.models.stdlib.contextlib", "ContextDecoratorModel"),
    "ContextManagerModel": ("pysymex.models.stdlib.contextlib", "ContextManagerModel"),
    "ExitStackModel": ("pysymex.models.stdlib.contextlib", "ExitStackModel"),
    "get_contextlib_model": ("pysymex.models.stdlib.contextlib", "get_contextlib_model"),
    "DATACLASSES_MODELS": ("pysymex.models.stdlib.dataclasses", "DATACLASSES_MODELS"),
    "FieldInfo": ("pysymex.models.stdlib.dataclasses", "FieldInfo"),
    "asdict_model": ("pysymex.models.stdlib.dataclasses", "asdict_model"),
    "astuple_model": ("pysymex.models.stdlib.dataclasses", "astuple_model"),
    "dataclass_model": ("pysymex.models.stdlib.dataclasses", "dataclass_model"),
    "field_model": ("pysymex.models.stdlib.dataclasses", "field_model"),
    "fields_model": ("pysymex.models.stdlib.dataclasses", "fields_model"),
    "get_dataclasses_model": ("pysymex.models.stdlib.dataclasses", "get_dataclasses_model"),
    "is_dataclass_model": ("pysymex.models.stdlib.dataclasses", "is_dataclass_model"),
    "make_dataclass_model": ("pysymex.models.stdlib.dataclasses", "make_dataclass_model"),
    "replace_model": ("pysymex.models.stdlib.dataclasses", "replace_model"),
    "DICT_MODELS": ("pysymex.models.containers.dicts.registry", "DICT_MODELS"),
    "DictGetModel": ("pysymex.models.containers.dicts.access", "DictGetModel"),
    "DictItemsModel": ("pysymex.models.containers.dicts.views", "DictItemsModel"),
    "DictKeysModel": ("pysymex.models.containers.dicts.views", "DictKeysModel"),
    "DictValuesModel": ("pysymex.models.containers.dicts.views", "DictValuesModel"),
    "LIST_MODELS": ("pysymex.models.containers.lists.registry", "LIST_MODELS"),
    "ListAppendModel": ("pysymex.models.containers.lists.mutations.growth", "ListAppendModel"),
    "ListExtendModel": ("pysymex.models.containers.lists.mutations.growth", "ListExtendModel"),
    "ListInsertModel": ("pysymex.models.containers.lists.mutations.growth", "ListInsertModel"),
    "ListPopModel": ("pysymex.models.containers.lists.mutations.removal", "ListPopModel"),
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
    "REGEX_MODELS": ("pysymex.models.stdlib.regex", "REGEX_MODELS"),
    "PatternCompiler": ("pysymex.models.stdlib.regex", "PatternCompiler"),
    "ReCompileModel": ("pysymex.models.stdlib.regex", "ReCompileModel"),
    "ReEscapeModel": ("pysymex.models.stdlib.regex", "ReEscapeModel"),
    "ReFullmatchModel": ("pysymex.models.stdlib.regex", "ReFullmatchModel"),
    "ReSplitModel": ("pysymex.models.stdlib.regex", "ReSplitModel"),
    "ReSubModel": ("pysymex.models.stdlib.regex", "ReSubModel"),
    "compile_pattern": ("pysymex.models.stdlib.regex", "compile_pattern"),
    "SET_MODELS": ("pysymex.models.containers.sets.registry", "SET_MODELS"),
    "SetAddModel": ("pysymex.models.containers.sets.mutations.membership", "SetAddModel"),
    "SetClearModel": ("pysymex.models.containers.sets.mutations.pop_clear", "SetClearModel"),
    "SetContainsModel": ("pysymex.models.containers.sets.queries", "SetContainsModel"),
    "SetCopyModel": ("pysymex.models.containers.sets.operations", "SetCopyModel"),
    "SetDiscardModel": (
        "pysymex.models.containers.sets.mutations.membership",
        "SetDiscardModel",
    ),
    "SetIntersectionModel": (
        "pysymex.models.containers.sets.operations",
        "SetIntersectionModel",
    ),
    "SetLenModel": ("pysymex.models.containers.sets.queries", "SetLenModel"),
    "SetPopModel": ("pysymex.models.containers.sets.mutations.pop_clear", "SetPopModel"),
    "SetRemoveModel": (
        "pysymex.models.containers.sets.mutations.membership",
        "SetRemoveModel",
    ),
    "SetUnionModel": ("pysymex.models.containers.sets.operations", "SetUnionModel"),
    "SetDifferenceModel": (
        "pysymex.models.containers.sets.operations",
        "SetDifferenceModel",
    ),
    "SetSymmetricDifferenceModel": (
        "pysymex.models.containers.sets.operations",
        "SetSymmetricDifferenceModel",
    ),
    "SetIssubsetModel": ("pysymex.models.containers.sets.queries", "SetIssubsetModel"),
    "SetIssupersetModel": ("pysymex.models.containers.sets.queries", "SetIssupersetModel"),
    "SetIsdisjointModel": ("pysymex.models.containers.sets.queries", "SetIsdisjointModel"),
    "SetUpdateModel": ("pysymex.models.containers.sets.updates", "SetUpdateModel"),
    "SetIntersectionUpdateModel": (
        "pysymex.models.containers.sets.updates",
        "SetIntersectionUpdateModel",
    ),
}
