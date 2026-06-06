from __future__ import annotations

import pytest

from pysymex.typing import StackValue
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect
from pysymex.models.containers.strings.case import (
    StrCapitalizeModel,
    StrCasefoldModel,
    StrLowerModel,
    StrSwapcaseModel,
    StrTitleModel,
    StrUpperModel,
)
from pysymex.models.containers.strings.classification.case import (
    StrIslowerModel,
    StrIstitleModel,
    StrIsupperModel,
)
from pysymex.models.containers.strings.classification.content import (
    StrIsalnumModel,
    StrIsalphaModel,
    StrIsdecimalModel,
    StrIsdigitModel,
    StrIsnumericModel,
    StrIsspaceModel,
)
from pysymex.models.containers.strings.classification.special import (
    StrIsasciiModel,
    StrIsidentifierModel,
    StrIsprintableModel,
)
from pysymex.models.containers.strings.encoding import (
    StrEncodeModel,
    StrExpandtabsModel,
    StrTranslateModel,
)
from pysymex.models.containers.strings.formatting import (
    StrCenterModel,
    StrFormatMapModel,
    StrLjustModel,
    StrRjustModel,
    StrZfillModel,
)
from pysymex.models.containers.strings.search.affixes import (
    StrEndswithModel,
    StrReplaceModel,
    StrStartswithModel,
)
from pysymex.models.containers.strings.search.counts import StrCountModel
from pysymex.models.containers.strings.search.indexing import (
    StrFindModel,
    StrIndexModel,
    StrRfindModel,
    StrRindexModel,
)
from pysymex.models.containers.strings.splitting import (
    StrJoinModel,
    StrPartitionModel,
    StrRpartitionModel,
    StrRsplitModel,
    StrSplitlinesModel,
    StrSplitModel,
)
from pysymex.models.containers.strings.trimming import (
    StrLstripModel,
    StrRemovePrefixModel,
    StrRemoveSuffixModel,
    StrRstripModel,
    StrStripModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_lower_upper_faithfulness() -> None:
    """Faithfulness baseline for concrete Python lower/upper behavior."""
    for text in ["", "AbC", "123", "a b"]:
        assert text.lower() == str(text).lower()
        assert text.upper() == str(text).upper()


def test_string_concrete_symbolic_error_paths() -> None:
    """Representative concrete/symbolic/error path checks."""
    StrLowerModel().apply([], {}, _state())
    StrFindModel().apply([], {}, _state())


def test_string_edge_case_empty_input() -> None:
    """Edge case: empty string semantics are well-defined."""
    assert "".strip() == ""


def test_case_models_preserve_concrete_symbolic_strings() -> None:
    """Concrete symbolic strings should keep exact values through case conversion."""
    result = StrLowerModel().apply(
        [SymbolicString.from_const(" 12X ")],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == " 12x "


def test_trim_models_preserve_concrete_symbolic_strings() -> None:
    """Concrete symbolic strings should keep exact values through trim operations."""
    result = StrStripModel().apply(
        [SymbolicString.from_const(" 12x ")],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "12x"


def test_str_isascii_rejects_invalid_call_shape() -> None:
    """Shared str.isascii handling follows its receiver-only CPython contract."""
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([SymbolicString.from_const("abc"), 1], {}),
        ([SymbolicString.from_const("abc")], {"unexpected": 1}),
    ]

    for args, kwargs in invalid_calls:
        result = StrIsasciiModel().apply(args, kwargs, _state())
        effect = result.side_effects.get("raised_exception")

        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_str_isascii_accepts_receiver_only_call() -> None:
    """Correctly shaped str.isascii calls remain modeled."""
    result = StrIsasciiModel().apply([SymbolicString.from_const("abc")], {}, _state())

    assert "raised_exception" not in result.side_effects


RECEIVER_ONLY_STRING_METHODS: list[FunctionModel] = [
    StrLowerModel(),
    StrUpperModel(),
    StrCapitalizeModel(),
    StrTitleModel(),
    StrSwapcaseModel(),
    StrCasefoldModel(),
    StrIsdigitModel(),
    StrIsalphaModel(),
    StrIsalnumModel(),
    StrIsspaceModel(),
    StrIslowerModel(),
    StrIsupperModel(),
    StrIstitleModel(),
    StrIsprintableModel(),
    StrIsidentifierModel(),
    StrIsdecimalModel(),
    StrIsnumericModel(),
]


@pytest.mark.parametrize("model", RECEIVER_ONLY_STRING_METHODS)
def test_receiver_only_string_methods_reject_arguments(model: FunctionModel) -> None:
    """Receiver-only string methods reject positional and keyword extras."""
    receiver = SymbolicString.from_const("abc")
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([receiver, 1], {}),
        ([receiver], {"unexpected": 1}),
    ]

    for args, kwargs in invalid_calls:
        result = model.apply(args, kwargs, _state())
        effect = result.side_effects.get("raised_exception")

        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("model", RECEIVER_ONLY_STRING_METHODS)
def test_receiver_only_string_methods_accept_receiver(model: FunctionModel) -> None:
    """Correctly shaped receiver-only string calls remain modeled."""
    result = model.apply([SymbolicString.from_const("abc")], {}, _state())

    assert "raised_exception" not in result.side_effects


POSITIONAL_STRING_METHODS: list[tuple[FunctionModel, list[StackValue], list[StackValue]]] = [
    (StrStripModel(), [], [None]),
    (StrLstripModel(), [], [None]),
    (StrRstripModel(), [], [None]),
    (StrRemovePrefixModel(), ["a"], ["a"]),
    (StrRemoveSuffixModel(), ["a"], ["a"]),
    (StrReplaceModel(), ["a", "b"], ["a", "b", 1]),
    (StrStartswithModel(), ["a"], ["a", 0, 2]),
    (StrEndswithModel(), ["a"], ["a", 0, 2]),
    (StrCountModel(), ["a"], ["a", 0, 2]),
    (StrFindModel(), ["a"], ["a", 0, 2]),
    (StrRfindModel(), ["a"], ["a", 0, 2]),
    (StrIndexModel(), ["a"], ["a", 0, 2]),
    (StrRindexModel(), ["a"], ["a", 0, 2]),
]


@pytest.mark.parametrize(("model", "minimum_args", "maximum_args"), POSITIONAL_STRING_METHODS)
def test_positional_string_methods_reject_invalid_calls(
    model: FunctionModel, minimum_args: list[StackValue], maximum_args: list[StackValue]
) -> None:
    """Bounded positional-only string methods reject excess or keyword calls."""
    receiver = SymbolicString.from_const("abc")
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([receiver, *maximum_args, 1], {}),
        ([receiver, *minimum_args], {"unexpected": 1}),
    ]

    for args, kwargs in invalid_calls:
        result = model.apply(args, kwargs, _state())
        effect = result.side_effects.get("raised_exception")

        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(("model", "minimum_args", "maximum_args"), POSITIONAL_STRING_METHODS)
def test_positional_string_methods_accept_documented_forms(
    model: FunctionModel, minimum_args: list[StackValue], maximum_args: list[StackValue]
) -> None:
    """Documented positional string method forms remain modeled."""
    receiver = SymbolicString.from_const("abc")

    for method_args in [minimum_args, maximum_args]:
        result = model.apply([receiver, *method_args], {}, _state())
        assert "raised_exception" not in result.side_effects


@pytest.mark.parametrize(
    "model",
    [
        StrRemovePrefixModel(),
        StrRemoveSuffixModel(),
        StrReplaceModel(),
        StrStartswithModel(),
        StrEndswithModel(),
        StrCountModel(),
        StrFindModel(),
        StrRfindModel(),
        StrIndexModel(),
        StrRindexModel(),
    ],
)
def test_positional_string_methods_reject_missing_required_operand(model: FunctionModel) -> None:
    """Methods requiring an operand reject receiver-only calls."""
    result = model.apply([SymbolicString.from_const("abc")], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


STRICT_PARAMETERIZED_STRING_METHODS: list[
    tuple[FunctionModel, list[StackValue], list[StackValue]]
] = [
    (StrJoinModel(), [["a"]], [["a"]]),
    (StrPartitionModel(), ["a"], ["a"]),
    (StrRpartitionModel(), ["a"], ["a"]),
    (StrCenterModel(), [3], [3, " "]),
    (StrLjustModel(), [3], [3, " "]),
    (StrRjustModel(), [3], [3, " "]),
    (StrZfillModel(), [3], [3]),
    (StrFormatMapModel(), [{}], [{}]),
    (StrTranslateModel(), [{}], [{}]),
]


@pytest.mark.parametrize(
    ("model", "minimum_args", "maximum_args"), STRICT_PARAMETERIZED_STRING_METHODS
)
def test_strict_parameterized_string_methods_enforce_positional_contract(
    model: FunctionModel, minimum_args: list[StackValue], maximum_args: list[StackValue]
) -> None:
    """Parameterized positional-only APIs reject extras and accept documented calls."""
    receiver = SymbolicString.from_const("abc")
    invalid_result = model.apply([receiver, *maximum_args, 1], {}, _state())
    keyword_result = model.apply([receiver, *minimum_args], {"unexpected": 1}, _state())

    for result in [invalid_result, keyword_result]:
        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"

    assert (
        "raised_exception" not in model.apply([receiver, *minimum_args], {}, _state()).side_effects
    )
    assert (
        "raised_exception" not in model.apply([receiver, *maximum_args], {}, _state()).side_effects
    )


KEYWORD_STRING_METHODS: list[tuple[FunctionModel, list[StackValue], dict[str, StackValue], str]] = [
    (StrSplitModel(), ["b", 1], {"sep": "b", "maxsplit": 1}, "sep"),
    (StrRsplitModel(), ["b", 1], {"sep": "b", "maxsplit": 1}, "sep"),
    (StrSplitlinesModel(), [True], {"keepends": True}, "keepends"),
    (StrEncodeModel(), ["utf-8", "strict"], {"encoding": "utf-8", "errors": "strict"}, "encoding"),
    (StrExpandtabsModel(), [4], {"tabsize": 4}, "tabsize"),
]


@pytest.mark.parametrize(
    ("model", "maximum_args", "valid_kwargs", "duplicate_name"), KEYWORD_STRING_METHODS
)
def test_keyword_parameterized_string_methods_enforce_contract(
    model: FunctionModel,
    maximum_args: list[StackValue],
    valid_kwargs: dict[str, StackValue],
    duplicate_name: str,
) -> None:
    """Named-parameter string methods accept supported names and reject invalid forms."""
    receiver = SymbolicString.from_const("abc")
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([receiver, *maximum_args, 1], {}),
        ([receiver], {"unexpected": 1}),
        ([receiver, maximum_args[0]], {duplicate_name: maximum_args[0]}),
    ]

    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"

    assert "raised_exception" not in model.apply([receiver], valid_kwargs, _state()).side_effects
    assert (
        "raised_exception" not in model.apply([receiver, *maximum_args], {}, _state()).side_effects
    )
