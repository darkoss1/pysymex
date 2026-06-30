from __future__ import annotations

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.builtins.types.containers.bytes.decoding import BytesDecodeModel
from pysymex._internal.models.builtins.types.containers.bytes.formatting import (
    BytesCenterModel,
    BytesHexModel,
    BytesLjustModel,
    BytesRjustModel,
    BytesZfillModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.search.affixes import (
    BytesEndswithModel,
    BytesStartswithModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.search.counts import BytesCountModel
from pysymex._internal.models.builtins.types.containers.bytes.search.indexing import (
    BytesFindModel,
    BytesIndexModel,
    BytesRfindModel,
    BytesRindexModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.splitting import (
    BytesJoinModel,
    BytesPartitionModel,
    BytesRpartitionModel,
    BytesRsplitModel,
    BytesSplitlinesModel,
    BytesSplitModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.transforms.replace import (
    BytesReplaceModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.transforms.trimming import (
    BytesLstripModel,
    BytesRemovePrefixModel,
    BytesRemoveSuffixModel,
    BytesRstripModel,
    BytesStripModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.translation import (
    BytesExpandtabsModel,
    BytesTranslateModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def _receiver() -> SymbolicList:
    return SymbolicList.empty("bytes_receiver")


POSITIONAL_BYTES_METHODS: list[tuple[FunctionModel, list[StackValue], list[StackValue]]] = [
    (BytesStripModel(), [], [b" "]),
    (BytesLstripModel(), [], [b" "]),
    (BytesRstripModel(), [], [b" "]),
    (BytesRemovePrefixModel(), [b"a"], [b"a"]),
    (BytesRemoveSuffixModel(), [b"a"], [b"a"]),
    (BytesStartswithModel(), [b"a"], [b"a", 0, 2]),
    (BytesEndswithModel(), [b"a"], [b"a", 0, 2]),
    (BytesCountModel(), [b"a"], [b"a", 0, 2]),
    (BytesFindModel(), [b"a"], [b"a", 0, 2]),
    (BytesRfindModel(), [b"a"], [b"a", 0, 2]),
    (BytesIndexModel(), [b"a"], [b"a", 0, 2]),
    (BytesRindexModel(), [b"a"], [b"a", 0, 2]),
    (BytesReplaceModel(), [b"a", b"b"], [b"a", b"b", 1]),
    (BytesJoinModel(), [[b"a"]], [[b"a"]]),
    (BytesPartitionModel(), [b"a"], [b"a"]),
    (BytesRpartitionModel(), [b"a"], [b"a"]),
    (BytesCenterModel(), [3], [3, b" "]),
    (BytesLjustModel(), [3], [3, b" "]),
    (BytesRjustModel(), [3], [3, b" "]),
    (BytesZfillModel(), [3], [3]),
]


@pytest.mark.parametrize(("model", "minimum_args", "maximum_args"), POSITIONAL_BYTES_METHODS)
def test_positional_bytes_methods_enforce_contract(
    model: FunctionModel, minimum_args: list[StackValue], maximum_args: list[StackValue]
) -> None:
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([_receiver(), *maximum_args, 1], {}),
        ([_receiver(), *minimum_args], {"unexpected": 1}),
    ]
    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"

    assert (
        "raised_exception"
        not in model.apply([_receiver(), *minimum_args], {}, _state()).side_effects
    )
    assert (
        "raised_exception"
        not in model.apply([_receiver(), *maximum_args], {}, _state()).side_effects
    )


@pytest.mark.parametrize(
    "model",
    [
        BytesRemovePrefixModel(),
        BytesRemoveSuffixModel(),
        BytesStartswithModel(),
        BytesEndswithModel(),
        BytesCountModel(),
        BytesFindModel(),
        BytesRfindModel(),
        BytesIndexModel(),
        BytesRindexModel(),
        BytesReplaceModel(),
        BytesJoinModel(),
        BytesPartitionModel(),
        BytesRpartitionModel(),
        BytesCenterModel(),
        BytesLjustModel(),
        BytesRjustModel(),
        BytesZfillModel(),
    ],
)
def test_bytes_methods_reject_missing_required_operand(model: FunctionModel) -> None:
    effect = model.apply([_receiver()], {}, _state()).side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


NAMED_BYTES_METHODS: list[
    tuple[FunctionModel, list[StackValue], list[StackValue], dict[str, StackValue], str]
] = [
    (BytesSplitModel(), [], [b"a", 1], {"sep": b"a", "maxsplit": 1}, "sep"),
    (BytesRsplitModel(), [], [b"a", 1], {"sep": b"a", "maxsplit": 1}, "sep"),
    (BytesSplitlinesModel(), [], [True], {"keepends": True}, "keepends"),
    (BytesHexModel(), [], [b" ", 1], {"sep": b" ", "bytes_per_sep": 1}, "sep"),
    (
        BytesDecodeModel(),
        [],
        ["utf-8", "strict"],
        {"encoding": "utf-8", "errors": "strict"},
        "encoding",
    ),
    (BytesTranslateModel(), [None], [None, b"a"], {"delete": b"a"}, "delete"),
    (BytesExpandtabsModel(), [], [4], {"tabsize": 4}, "tabsize"),
]


@pytest.mark.parametrize(
    ("model", "base_args", "maximum_args", "valid_kwargs", "duplicate_name"), NAMED_BYTES_METHODS
)
def test_named_bytes_methods_enforce_contract(
    model: FunctionModel,
    base_args: list[StackValue],
    maximum_args: list[StackValue],
    valid_kwargs: dict[str, StackValue],
    duplicate_name: str,
) -> None:
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([_receiver(), *maximum_args, 1], {}),
        ([_receiver(), *base_args], {"unexpected": 1}),
        ([_receiver(), *maximum_args], {duplicate_name: maximum_args[-1]}),
    ]
    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"

    assert (
        "raised_exception"
        not in model.apply([_receiver(), *base_args], valid_kwargs, _state()).side_effects
    )
    assert (
        "raised_exception"
        not in model.apply([_receiver(), *maximum_args], {}, _state()).side_effects
    )
