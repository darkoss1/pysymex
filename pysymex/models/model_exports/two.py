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

MODEL_EXPORTS_2 = {
    "SetDifferenceUpdateModel": (
        "pysymex.models.containers.sets.updates",
        "SetDifferenceUpdateModel",
    ),
    "SetSymmetricDifferenceUpdateModel": (
        "pysymex.models.containers.sets.updates",
        "SetSymmetricDifferenceUpdateModel",
    ),
    "TUPLE_MODELS": ("pysymex.models.containers.tuples.registry", "TUPLE_MODELS"),
    "TupleModel": ("pysymex.models.containers.tuples.construction", "TupleModel"),
    "TupleGetitemModel": ("pysymex.models.containers.tuples.queries", "TupleGetitemModel"),
    "TupleContainsModel": ("pysymex.models.containers.tuples.queries", "TupleContainsModel"),
    "TupleLenModel": ("pysymex.models.containers.tuples.queries", "TupleLenModel"),
    "TupleCountModel": ("pysymex.models.containers.tuples.queries", "TupleCountModel"),
    "TupleIndexModel": ("pysymex.models.containers.tuples.queries", "TupleIndexModel"),
    "TupleAddModel": ("pysymex.models.containers.tuples.operations", "TupleAddModel"),
    "TupleMulModel": ("pysymex.models.containers.tuples.operations", "TupleMulModel"),
    "TupleSliceModel": ("pysymex.models.containers.tuples.operations", "TupleSliceModel"),
    "TupleEqModel": ("pysymex.models.containers.tuples.operations", "TupleEqModel"),
    "TupleHashModel": ("pysymex.models.containers.tuples.operations", "TupleHashModel"),
    "ListSetitemModel": ("pysymex.models.containers.lists.items", "ListSetitemModel"),
    "ListDelitemModel": ("pysymex.models.containers.lists.items", "ListDelitemModel"),
    "ListAddModel": ("pysymex.models.containers.lists.operators", "ListAddModel"),
    "ListMulModel": ("pysymex.models.containers.lists.operators", "ListMulModel"),
    "ListEqModel": ("pysymex.models.containers.lists.queries", "ListEqModel"),
    "ListIaddModel": ("pysymex.models.containers.lists.operators", "ListIaddModel"),
    "ListImulModel": ("pysymex.models.containers.lists.operators", "ListImulModel"),
    "ExecModel": ("pysymex.models.builtins", "ExecModel"),
    "EvalModel": ("pysymex.models.builtins", "EvalModel"),
    "CompileModel": ("pysymex.models.builtins", "CompileModel"),
    "BinModel": ("pysymex.models.builtins", "BinModel"),
    "OctModel": ("pysymex.models.builtins", "OctModel"),
    "HexModel": ("pysymex.models.builtins", "HexModel"),
    "BytesModel": ("pysymex.models.builtins", "BytesModel"),
    "BytearrayModel": ("pysymex.models.builtins", "BytearrayModel"),
    "FrozensetModel": ("pysymex.models.builtins", "FrozensetModel"),
    "MemoryviewModel": ("pysymex.models.builtins", "MemoryviewModel"),
    "ObjectModel": ("pysymex.models.builtins", "ObjectModel"),
    "PropertyModel": ("pysymex.models.builtins", "PropertyModel"),
    "ClassmethodModel": ("pysymex.models.builtins", "ClassmethodModel"),
    "StaticmethodModel": ("pysymex.models.builtins", "StaticmethodModel"),
    "VarsModel": ("pysymex.models.builtins", "VarsModel"),
    "DirModel": ("pysymex.models.builtins", "DirModel"),
    "AsciiModel": ("pysymex.models.builtins", "AsciiModel"),
    "BreakpointModel": ("pysymex.models.builtins", "BreakpointModel"),
    "BYTES_MODELS": ("pysymex.models.containers.bytes.registry", "BYTES_MODELS"),
    "FROZENSET_MODELS": ("pysymex.models.containers.frozensets.registry", "FROZENSET_MODELS"),
    "INT_FLOAT_MODELS": ("pysymex.models.numeric", "INT_FLOAT_MODELS"),
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
    "STRING_MODELS": ("pysymex.models.containers.strings.registry", "STRING_MODELS"),
    "StrJoinModel": ("pysymex.models.containers.strings.splitting", "StrJoinModel"),
    "StrLowerModel": ("pysymex.models.containers.strings.case", "StrLowerModel"),
    "StrReplaceModel": ("pysymex.models.containers.strings.search.affixes", "StrReplaceModel"),
    "StrSplitModel": ("pysymex.models.containers.strings.splitting", "StrSplitModel"),
    "StrStripModel": ("pysymex.models.containers.strings.trimming", "StrStripModel"),
    "StrUpperModel": ("pysymex.models.containers.strings.case", "StrUpperModel"),
    "THREADING_MODELS": ("pysymex.models.concurrency.threading.registry", "THREADING_MODELS"),
    "BarrierModel": ("pysymex.models.concurrency.threading.sync", "BarrierModel"),
    "ThreadingConditionModel": ("pysymex.models.concurrency.threading.sync", "ConditionModel"),
    "ThreadingEventModel": ("pysymex.models.concurrency.threading.sync", "EventModel"),
    "ThreadingLockModel": ("pysymex.models.concurrency.threading.locks", "LockModel"),
    "RLockModel": ("pysymex.models.concurrency.threading.locks", "RLockModel"),
    "ThreadingSemaphoreModel": ("pysymex.models.concurrency.threading.locks", "SemaphoreModel"),
    "ThreadModel": ("pysymex.models.concurrency.threading.threads", "ThreadModel"),
    "get_threading_model": (
        "pysymex.models.concurrency.threading.registry",
        "get_threading_model",
    ),
    "COLLECTIONS_MODELS": ("pysymex.models.stdlib.collections", "COLLECTIONS_MODELS"),
    "ChainMapModel": ("pysymex.models.stdlib.collections", "ChainMapModel"),
    "DefaultDictModel": ("pysymex.models.stdlib.collections", "DefaultDictModel"),
}
