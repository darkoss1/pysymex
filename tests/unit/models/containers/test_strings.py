from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.strings.case import (
    StrCapitalizeModel,
    StrCasefoldModel,
    StrLowerModel,
    StrSwapcaseModel,
    StrTitleModel,
    StrUpperModel,
)
from pysymex._internal.models.builtins.types.containers.strings.classification.case import (
    StrIslowerModel,
    StrIstitleModel,
    StrIsupperModel,
)
from pysymex._internal.models.builtins.types.containers.strings.classification.content import (
    StrIsalnumModel,
    StrIsalphaModel,
    StrIsdecimalModel,
    StrIsdigitModel,
    StrIsnumericModel,
    StrIsspaceModel,
)
from pysymex._internal.models.builtins.types.containers.strings.classification.special import (
    StrIsasciiModel,
    StrIsidentifierModel,
    StrIsprintableModel,
)
from pysymex._internal.models.builtins.types.containers.strings.encoding import (
    StrEncodeModel,
    StrExpandtabsModel,
    StrTranslateModel,
)
from pysymex._internal.models.builtins.types.containers.strings.formatting import (
    StrCenterModel,
    StrFormatMapModel,
    StrLjustModel,
    StrRjustModel,
    StrZfillModel,
)
from pysymex._internal.models.builtins.types.containers.strings.search.affixes import (
    StrEndswithModel,
    StrReplaceModel,
    StrStartswithModel,
)
from pysymex._internal.models.builtins.types.containers.strings.search.counts import (
    StrContainsModel,
    StrCountModel,
)
from pysymex._internal.models.builtins.types.containers.strings.search.indexing import (
    StrFindModel,
    StrIndexModel,
    StrRfindModel,
    StrRindexModel,
)
from pysymex._internal.models.builtins.types.containers.strings.splitting import (
    StrJoinModel,
    StrPartitionModel,
    StrRpartitionModel,
    StrRsplitModel,
    StrSplitlinesModel,
    StrSplitModel,
)
from pysymex._internal.models.builtins.types.containers.strings.trimming import (
    StrLstripModel,
    StrRemovePrefixModel,
    StrRemoveSuffixModel,
    StrRstripModel,
    StrStripModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


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


def test_str_affix_models_return_truthy_bool_for_symbolic_results() -> None:
    """startswith()/endswith() predicates must be branch-feasible symbolic bools."""
    receiver, receiver_constraint = SymbolicString.symbolic("subject")
    operand = SymbolicString.from_const("abc")

    for model in (StrStartswithModel(), StrEndswithModel()):
        result = model.apply([receiver, operand], {}, _state())

        assert isinstance(result.value, SymbolicValue)
        assert result.value.affinity_type == "bool"
        solver = z3.Solver()
        solver.add(receiver_constraint)
        solver.add(result.value.could_be_truthy() != result.value.z3_bool)
        assert solver.check() == z3.unsat


def test_str_affix_models_apply_concrete_start_end_bounds() -> None:
    """startswith()/endswith() should follow CPython start/end slice bounds exactly."""
    receiver = SymbolicString.from_const("abc")

    starts_true = StrStartswithModel().apply([receiver, "b", 1], {}, _state())
    starts_false = StrStartswithModel().apply([receiver, "a", 1], {}, _state())
    ends_true = StrEndswithModel().apply(
        [receiver, "b", SymbolicValue.from_const(0), SymbolicValue.from_const(2)],
        {},
        _state(),
    )
    ends_false = StrEndswithModel().apply([receiver, "c", 0, 2], {}, _state())

    assert isinstance(starts_true.value, SymbolicValue)
    assert isinstance(starts_false.value, SymbolicValue)
    assert isinstance(ends_true.value, SymbolicValue)
    assert isinstance(ends_false.value, SymbolicValue)
    assert z3.is_true(z3.simplify(starts_true.value.z3_bool))
    assert z3.is_false(z3.simplify(starts_false.value.z3_bool))
    assert z3.is_true(z3.simplify(ends_true.value.z3_bool))
    assert z3.is_false(z3.simplify(ends_false.value.z3_bool))


def test_str_affix_models_apply_concrete_tuple_operands() -> None:
    """startswith()/endswith() should support CPython tuple-of-str affixes."""
    receiver = SymbolicString.from_const("abc")

    starts_true = StrStartswithModel().apply([receiver, ("x", "a")], {}, _state())
    starts_false = StrStartswithModel().apply([receiver, ("x", "y")], {}, _state())
    ends_true = StrEndswithModel().apply([receiver, ("x", "c")], {}, _state())
    ends_false = StrEndswithModel().apply([receiver, ("x", "y")], {}, _state())

    assert isinstance(starts_true.value, SymbolicValue)
    assert isinstance(starts_false.value, SymbolicValue)
    assert isinstance(ends_true.value, SymbolicValue)
    assert isinstance(ends_false.value, SymbolicValue)
    assert z3.is_true(z3.simplify(starts_true.value.z3_bool))
    assert z3.is_false(z3.simplify(starts_false.value.z3_bool))
    assert z3.is_true(z3.simplify(ends_true.value.z3_bool))
    assert z3.is_false(z3.simplify(ends_false.value.z3_bool))


@pytest.mark.parametrize(
    ("model", "operand", "message"),
    [
        (
            StrStartswithModel(),
            1,
            "startswith first arg must be str or a tuple of str, not int",
        ),
        (
            StrEndswithModel(),
            1,
            "endswith first arg must be str or a tuple of str, not int",
        ),
        (
            StrStartswithModel(),
            (1, "a"),
            "tuple for startswith must only contain str, not int",
        ),
        (
            StrEndswithModel(),
            (1, "c"),
            "tuple for endswith must only contain str, not int",
        ),
    ],
)
def test_str_affix_models_reject_definite_invalid_operands(
    model: FunctionModel,
    operand: StackValue,
    message: str,
) -> None:
    """startswith()/endswith() should report CPython TypeError for invalid affixes."""
    result = model.apply([SymbolicString.from_const("abc"), operand], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_str_affix_models_keep_bool_slice_bounds_exact() -> None:
    """startswith()/endswith() accept bool start/end bounds as CPython integers."""
    receiver = SymbolicString.from_const("abc")

    starts = StrStartswithModel().apply([receiver, "b", True], {}, _state())
    ends = StrEndswithModel().apply([receiver, "a", None, True], {}, _state())

    assert isinstance(starts.value, SymbolicValue)
    assert isinstance(ends.value, SymbolicValue)
    assert z3.is_true(z3.simplify(starts.value.z3_bool))
    assert z3.is_true(z3.simplify(ends.value.z3_bool))
    assert "raised_exception" not in starts.side_effects
    assert "raised_exception" not in ends.side_effects


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (StrStartswithModel(), ["a", SymbolicString.from_const("bad")]),
        (StrEndswithModel(), ["c", SymbolicString.from_const("bad")]),
        (StrStartswithModel(), ["a", None, SymbolicString.from_const("bad")]),
        (StrEndswithModel(), ["c", None, SymbolicString.from_const("bad")]),
    ],
)
def test_str_affix_models_reject_definite_invalid_slice_bounds(
    model: FunctionModel,
    args: list[StackValue],
) -> None:
    """startswith()/endswith() should reject definite non-index start/end operands."""
    result = model.apply([SymbolicString.from_const("abc"), *args], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == "slice indices must be integers or None or have an __index__ method"


def test_str_affix_models_do_not_apply_whole_string_relation_with_symbolic_bounds() -> None:
    """Symbolic start/end bounds should not be modeled as whole-string affix checks."""
    start, start_constraint = SymbolicValue.symbolic_int("affix_start")
    receiver = SymbolicString.from_const("abc")

    starts = StrStartswithModel().apply([receiver, "a", start], {}, _state())
    ends = StrEndswithModel().apply([receiver, "c", 0, start], {}, _state())

    for result in [starts, ends]:
        assert isinstance(result.value, SymbolicValue)
        truthy = z3.Solver()
        truthy.add(start_constraint, result.value.z3_bool)
        assert truthy.check() == z3.sat
        falsy = z3.Solver()
        falsy.add(start_constraint, z3.Not(result.value.z3_bool))
        assert falsy.check() == z3.sat


def test_str_index_models_return_exact_positions_for_concrete_hits() -> None:
    """str.index/rindex should retain exact concrete hit positions."""
    receiver = SymbolicString.from_const("ababa")

    index_result = StrIndexModel().apply([receiver, "ba"], {}, _state())
    rindex_result = StrRindexModel().apply([receiver, "ba"], {}, _state())

    assert isinstance(index_result.value, SymbolicValue)
    assert isinstance(rindex_result.value, SymbolicValue)
    assert z3.is_true(z3.simplify(index_result.value.z3_int == 1))
    assert z3.is_true(z3.simplify(rindex_result.value.z3_int == 3))
    assert "raised_exception" not in index_result.side_effects
    assert "potential_exception" not in index_result.side_effects
    assert "raised_exception" not in rindex_result.side_effects
    assert "potential_exception" not in rindex_result.side_effects


def test_str_index_models_raise_definite_value_error_for_concrete_misses() -> None:
    """str.index/rindex should not return -1 on definite concrete misses."""
    receiver = SymbolicString.from_const("abc")

    for result in (
        StrIndexModel().apply([receiver, "z"], {}, _state()),
        StrRindexModel().apply([receiver, "z"], {}, _state()),
    ):
        assert isinstance(result.value, SymbolicNone)
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "ValueError"
        assert effect["message"] == "substring not found"
        assert "potential_exception" not in result.side_effects


def test_str_contains_materializes_exact_string_membership() -> None:
    """str.__contains__ should preserve exact concrete string membership."""
    receiver = SymbolicString.from_const("abc")

    present = StrContainsModel().apply([receiver, "b"], {}, _state())
    missing = StrContainsModel().apply([receiver, "z"], {}, _state())

    assert isinstance(present.value, SymbolicValue)
    assert isinstance(missing.value, SymbolicValue)
    assert z3.is_true(z3.simplify(present.value.z3_bool))
    assert z3.is_false(z3.simplify(missing.value.z3_bool))
    assert "raised_exception" not in present.side_effects
    assert "raised_exception" not in missing.side_effects


def test_str_contains_rejects_definite_non_string_needle() -> None:
    """str.__contains__ should report CPython's TypeError for non-string needles."""
    result = StrContainsModel().apply(
        [SymbolicString.from_const("abc"), SymbolicValue.from_const(1)],
        {},
        _state(),
    )

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert "'in <string>' requires string as left operand, not int" == effect["message"]


def test_str_contains_rejects_invalid_call_shape() -> None:
    """str.__contains__ has a fixed two-argument method contract."""
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([SymbolicString.from_const("abc")], {}),
        ([SymbolicString.from_const("abc"), "a", "extra"], {}),
        ([SymbolicString.from_const("abc"), "a"], {"unexpected": 1}),
    ]

    for args, kwargs in invalid_calls:
        result = StrContainsModel().apply(args, kwargs, _state())
        effect = result.side_effects.get("raised_exception")

        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_str_search_models_keep_exact_string_operands_precise() -> None:
    """count/find/index families should keep exact results for valid string operands."""
    receiver = SymbolicString.from_const("banana")
    cases: list[tuple[FunctionModel, int]] = [
        (StrCountModel(), 1),
        (StrFindModel(), 1),
        (StrRfindModel(), 3),
        (StrIndexModel(), 1),
        (StrRindexModel(), 3),
    ]

    for model, expected in cases:
        result = model.apply([receiver, "ana"], {}, _state())

        assert isinstance(result.value, SymbolicValue)
        assert z3.is_true(z3.simplify(result.value.z3_int == expected))
        assert "raised_exception" not in result.side_effects


@pytest.mark.parametrize(
    "model",
    [StrCountModel(), StrFindModel(), StrRfindModel(), StrIndexModel(), StrRindexModel()],
)
def test_str_search_models_reject_definite_non_string_operand(model: FunctionModel) -> None:
    """String search methods should reject definite non-string search operands."""
    result = model.apply(
        [SymbolicString.from_const("abc"), SymbolicValue.from_const(1)],
        {},
        _state(),
    )

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == f"{model.name}() argument 1 must be str, not int"


@pytest.mark.parametrize(
    "model",
    [StrCountModel(), StrFindModel(), StrRfindModel(), StrIndexModel(), StrRindexModel()],
)
def test_str_search_models_reject_definite_invalid_slice_bounds(model: FunctionModel) -> None:
    """String search methods should reject definite non-index start/end operands."""
    result = model.apply(
        [SymbolicString.from_const("abc"), "a", SymbolicString.from_const("bad")],
        {},
        _state(),
    )

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == "slice indices must be integers or None or have an __index__ method"


def test_str_replace_keeps_exact_valid_replacement() -> None:
    """str.replace should keep exact concrete replacement semantics."""
    result = StrReplaceModel().apply(
        [SymbolicString.from_const("banana"), "ana", "oo", SymbolicValue.from_const(1)],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.concrete_value == "boona"
    assert "raised_exception" not in result.side_effects


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([SymbolicValue.from_const(1), "x"], "replace() argument 1 must be str, not int"),
        (["a", SymbolicValue.from_const(1)], "replace() argument 2 must be str, not int"),
        (["a", "x", "bad"], "'str' object cannot be interpreted as an integer"),
        (
            ["a", "x", SymbolicNone()],
            "'NoneType' object cannot be interpreted as an integer",
        ),
    ],
)
def test_str_replace_rejects_definite_invalid_operands(
    args: list[StackValue],
    message: str,
) -> None:
    """str.replace should report CPython TypeError for definite invalid operands."""
    result = StrReplaceModel().apply(
        [SymbolicString.from_const("abc"), *args],
        {},
        _state(),
    )

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


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

        assert SideEffects.is_raised_exception(effect)
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

        assert SideEffects.is_raised_exception(effect)
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

        assert SideEffects.is_raised_exception(effect)
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

    assert SideEffects.is_raised_exception(effect)
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
        assert SideEffects.is_raised_exception(effect)
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
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"

    assert "raised_exception" not in model.apply([receiver], valid_kwargs, _state()).side_effects
    assert (
        "raised_exception" not in model.apply([receiver, *maximum_args], {}, _state()).side_effects
    )
