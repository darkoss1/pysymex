from __future__ import annotations

import pytest
import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import (
    FunctionModel,
    is_raised_exception_effect,
    is_sink_event_effect,
)
from pysymex.typing import StackValue
import pysymex.models.builtins as extended


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    "model",
    [
        extended.IterModel(),
        extended.NextModel(),
        extended.ReversedModel(),
        extended.AiterModel(),
        extended.AnextModel(),
        extended.IdModel(),
        extended.HashModel(),
        extended.CallableModel(),
        extended.ReprModel(),
        extended.FormatModel(),
        extended.OrdModel(),
        extended.ChrModel(),
        extended.PowModel(),
        extended.RoundModel(),
        extended.DivmodModel(),
        extended.BinModel(),
        extended.OctModel(),
        extended.HexModel(),
        extended.HasattrModel(),
        extended.GetattrModel(),
        extended.SetattrModel(),
        extended.DelattrModel(),
        extended.IssubclassModel(),
        extended.AsciiModel(),
        extended.ClassmethodModel(),
        extended.StaticmethodModel(),
        extended.MemoryviewModel(),
        extended.OpenModel(),
        extended.ExecModel(),
        extended.EvalModel(),
        extended.CompileModel(),
        extended.ImportModel(),
    ],
)
def test_required_argument_builtin_without_args_emits_type_error(model: FunctionModel) -> None:
    """Required-argument builtins reject missing positional arguments like CPython."""
    result = model.apply([], {}, _state())
    raised_effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised_effect)
    assert raised_effect["exception_type"] == "TypeError"


def test_super_without_class_closure_emits_runtime_error() -> None:
    """Zero-argument super() without a __class__ closure is invalid in CPython."""
    result = extended.SuperModel().apply([], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "RuntimeError"


def test_super_with_class_closure_remains_contextually_modeled() -> None:
    """A __class__ closure may support zero-argument super(); do not reject it."""
    result = extended.SuperModel().apply([], {}, VMState(pc=0, local_vars={"__class__": object}))

    assert "raised_exception" not in result.side_effects


@pytest.mark.parametrize("model", [extended.ExitModel(), extended.QuitModel()])
def test_terminal_builtin_emits_system_exit_and_rejects_extra_args(model: FunctionModel) -> None:
    """Interactive terminal helpers mirror their SystemExit/TypeError call contract."""
    successful = model.apply([7], {}, _state()).side_effects.get("raised_exception")
    assert is_raised_exception_effect(successful)
    assert successful["exception_type"] == "SystemExit"
    assert successful["message"] == "7"

    invalid = model.apply([1, 2], {}, _state()).side_effects.get("raised_exception")
    assert is_raised_exception_effect(invalid)
    assert invalid["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (extended.HelpModel(), []),
        (extended.HelpModel(), [1]),
        (extended.CopyrightModel(), []),
        (extended.CreditsModel(), []),
        (extended.LicenseModel(), []),
    ],
)
def test_interactive_output_builtins_record_io_without_rendering_host_text(
    model: FunctionModel, args: list[StackValue]
) -> None:
    """Interactive display builtins return None while output text stays abstract."""
    result = model.apply(args, {}, _state())

    assert result.side_effects.get("io") is True
    assert "raised_exception" not in result.side_effects


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (extended.HelpModel(), [1, 2]),
        (extended.CopyrightModel(), [1]),
        (extended.CreditsModel(), [1]),
        (extended.LicenseModel(), [1]),
    ],
)
def test_interactive_output_builtins_reject_excess_positional_arguments(
    model: FunctionModel, args: list[StackValue]
) -> None:
    """Interactive display builtins reject positional forms CPython rejects."""
    result = model.apply(args, {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    "model",
    [
        extended.HelpModel(),
        extended.CopyrightModel(),
        extended.CreditsModel(),
        extended.LicenseModel(),
    ],
)
def test_interactive_output_builtins_reject_keywords(model: FunctionModel) -> None:
    """Interactive display builtins reject keyword calls like CPython."""
    effect = model.apply([], {"x": 1}, _state()).side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_input_rejects_extra_positional_or_keyword_arguments() -> None:
    """input() only permits its optional positional prompt argument."""
    for result in (
        extended.InputModel().apply(["a", "b"], {}, _state()),
        extended.InputModel().apply([], {"prompt": "a"}, _state()),
    ):
        raised = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(raised)
        assert raised["exception_type"] == "TypeError"


def test_required_keyword_forms_remain_supported() -> None:
    """Required keyword forms accepted by CPython are not rejected as arity errors."""
    results = [
        extended.OpenModel().apply([], {"file": "report.txt"}, _state()),
        extended.CompileModel().apply(
            [], {"source": "1", "filename": "<test>", "mode": "eval"}, _state()
        ),
        extended.ImportModel().apply([], {"name": "math"}, _state()),
        extended.EvalModel().apply(["1"], {"globals": {}}, _state()),
        extended.ExecModel().apply(["x = 1"], {"closure": None}, _state()),
    ]
    assert all("raised_exception" not in result.side_effects for result in results)


@pytest.mark.parametrize("model", [extended.BytesModel(), extended.BytearrayModel()])
def test_binary_constructors_honor_named_source_length(model: FunctionModel) -> None:
    kwargs: dict[str, StackValue] = {"source": b"ab"}
    result = model.apply([], kwargs, _state())

    assert isinstance(result.value, SymbolicList)
    assert "raised_exception" not in result.side_effects
    solver = z3.Solver()
    solver.add(*result.constraints, result.value.z3_len != 2)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("model", [extended.BytesModel(), extended.BytearrayModel()])
def test_binary_constructors_reject_invalid_keyword_binding(model: FunctionModel) -> None:
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([], {"encoding": "utf-8"}),
        ([b"a"], {"source": b"a"}),
        (["a", "utf-8"], {"encoding": "utf-8"}),
        ([], {"unexpected": b"a"}),
    ]

    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


_DYNAMIC_INVALID_CALLS: list[
    tuple[FunctionModel, list[tuple[list[StackValue], dict[str, StackValue]]]]
] = [
    (
        extended.OpenModel(),
        [(["x"], {"file": "x"}), ([], {"unexpected": "x"}), (["x"] * 9, {})],
    ),
    (
        extended.CompileModel(),
        [(["1"], {"source": "1"}), ([], {"unexpected": "x"}), (["1"] * 7, {})],
    ),
    (
        extended.ImportModel(),
        [(["math"], {"name": "math"}), ([], {"unexpected": "x"}), (["math"] * 6, {})],
    ),
    (
        extended.EvalModel(),
        [([], {"source": "1"}), (["1", {}, {}, None], {}), (["1", {}], {"globals": {}})],
    ),
    (
        extended.ExecModel(),
        [
            ([], {"source": "x = 1"}),
            (["x = 1", {}, {}, None], {}),
            (["x = 1", {}], {"globals": {}}),
        ],
    ),
]


@pytest.mark.parametrize(("model", "invalid_calls"), _DYNAMIC_INVALID_CALLS)
def test_dynamic_builtins_reject_invalid_binding(
    model: FunctionModel,
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]],
) -> None:
    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_compile_keyword_symbolic_source_remains_critical_sink() -> None:
    kwargs: dict[str, StackValue] = {
        "source": SymbolicString.from_const("x + 1"),
        "filename": "<test>",
        "mode": "eval",
    }
    result = extended.CompileModel().apply([], kwargs, _state())
    sink_event = result.side_effects.get("sink_event")

    assert is_sink_event_effect(sink_event)
    assert sink_event["severity"] == "critical"


def test_property_accepts_named_descriptor_fields() -> None:
    kwargs: dict[str, StackValue] = {"fget": None, "doc": "value documentation"}
    result = extended.PropertyModel().apply([], kwargs, _state())

    assert "raised_exception" not in result.side_effects


def test_property_rejects_duplicate_or_unknown_fields() -> None:
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([None], {"fget": None}),
        ([], {"unknown": None}),
        ([None, None, None, None, None], {}),
    ]

    for args, kwargs in invalid_calls:
        effect = (
            extended.PropertyModel()
            .apply(args, kwargs, _state())
            .side_effects.get("raised_exception")
        )
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_pow_and_round_accept_named_parameters() -> None:
    pow_kwargs: dict[str, StackValue] = {"base": 2, "exp": 5}
    round_kwargs: dict[str, StackValue] = {"number": 3.14159, "ndigits": 2}
    pow_result = extended.PowModel().apply([], pow_kwargs, _state())
    round_result = extended.RoundModel().apply([], round_kwargs, _state())

    assert isinstance(pow_result.value, SymbolicValue)
    assert pow_result.value.value == 32
    assert round_result.value == 3.14


def test_pow_and_round_concrete_failures_are_modeled() -> None:
    invalid_mod = extended.PowModel().apply([2, 3, 1.5], {}, _state())
    zero_power = extended.PowModel().apply([0, -1], {}, _state())
    zero_modulus = extended.PowModel().apply([2, -1, 0], {}, _state())
    invalid_ndigits = extended.RoundModel().apply([1.5, 1.0], {}, _state())
    invalid_number = extended.RoundModel().apply(["1.5"], {}, _state())

    expected = [
        (invalid_mod, "TypeError"),
        (zero_power, "ZeroDivisionError"),
        (zero_modulus, "ValueError"),
        (invalid_ndigits, "TypeError"),
        (invalid_number, "TypeError"),
    ]
    for result, exception_type in expected:
        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == exception_type


def test_pow_and_round_reject_invalid_keyword_binding() -> None:
    invalid_calls: list[tuple[FunctionModel, list[StackValue], dict[str, StackValue]]] = [
        (extended.PowModel(), [2], {"base": 2, "exp": 5}),
        (extended.PowModel(), [], {"base": 2}),
        (extended.RoundModel(), [3.1], {"number": 3.1}),
        (extended.RoundModel(), [], {"ndigits": 2}),
    ]

    for model, args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"
