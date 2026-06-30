from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.attributes.descriptors import (
    AsciiModel,
    ClassmethodModel,
    PropertyModel,
    StaticmethodModel,
)
from pysymex._internal.models.builtins.attributes.getattr import GetattrModel
from pysymex._internal.models.builtins.attributes.mutation import (
    DelattrModel,
    HasattrModel,
    SetattrModel,
)
from pysymex._internal.models.builtins.bytes.constructors import BytearrayModel, BytesModel
from pysymex._internal.models.builtins.constructors.object import MemoryviewModel
from pysymex._internal.models.builtins.iteration.iter_model import IterModel
from pysymex._internal.models.builtins.iteration.next_model import NextModel
from pysymex._internal.models.builtins.iteration.reversed_model import ReversedModel
from pysymex._internal.models.builtins.numeric.format import (
    BinModel,
    DivmodModel,
    HexModel,
    OctModel,
)
from pysymex._internal.models.builtins.reflection.identity import (
    AiterModel,
    AnextModel,
    CallableModel,
    FormatModel,
    HashModel,
    IdModel,
    ReprModel,
)
from pysymex._internal.models.builtins.reflection.namespace import IssubclassModel, SuperModel
from pysymex._internal.models.builtins.reflection.type_checks import PrintModel
from pysymex._internal.models.builtins.runtime.dynamic_io import (
    BreakpointModel,
    CompileModel,
    EvalModel,
    ExecModel,
    ImportModel,
    InputModel,
    OpenModel,
)
from pysymex._internal.models.builtins.runtime.interactive import (
    CopyrightModel,
    CreditsModel,
    HelpModel,
    LicenseModel,
)
from pysymex._internal.models.builtins.runtime.terminal import ExitModel, QuitModel
from pysymex._internal.models.builtins.text.codepoints import (
    ChrModel,
    OrdModel,
    PowModel,
    RoundModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    "model",
    [
        IterModel(),
        NextModel(),
        ReversedModel(),
        AiterModel(),
        AnextModel(),
        IdModel(),
        HashModel(),
        CallableModel(),
        ReprModel(),
        FormatModel(),
        OrdModel(),
        ChrModel(),
        PowModel(),
        RoundModel(),
        DivmodModel(),
        BinModel(),
        OctModel(),
        HexModel(),
        HasattrModel(),
        GetattrModel(),
        SetattrModel(),
        DelattrModel(),
        IssubclassModel(),
        AsciiModel(),
        ClassmethodModel(),
        StaticmethodModel(),
        MemoryviewModel(),
        OpenModel(),
        ExecModel(),
        EvalModel(),
        CompileModel(),
        ImportModel(),
    ],
)
def test_required_argument_builtin_without_args_emits_type_error(model: FunctionModel) -> None:
    """Required-argument builtins reject missing positional arguments like CPython."""
    result = model.apply([], {}, _state())
    raised_effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised_effect)
    assert raised_effect["exception_type"] == "TypeError"


def test_super_without_class_closure_emits_runtime_error() -> None:
    """Zero-argument super() without a __class__ closure is invalid in CPython."""
    result = SuperModel().apply([], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "RuntimeError"


def test_super_with_class_closure_remains_contextually_modeled() -> None:
    """A __class__ closure may support zero-argument super(); do not reject it."""
    result = SuperModel().apply([], {}, VMState(pc=0, local_vars={"__class__": object}))

    assert "raised_exception" not in result.side_effects


@pytest.mark.parametrize("model", [ExitModel(), QuitModel()])
def test_terminal_builtin_emits_system_exit_and_rejects_extra_args(model: FunctionModel) -> None:
    """Interactive terminal helpers mirror their SystemExit/TypeError call contract."""
    successful = model.apply([7], {}, _state()).side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(successful)
    assert successful["exception_type"] == "SystemExit"
    assert successful["message"] == "7"

    invalid = model.apply([1, 2], {}, _state()).side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(invalid)
    assert invalid["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (HelpModel(), []),
        (HelpModel(), [1]),
        (CopyrightModel(), []),
        (CreditsModel(), []),
        (LicenseModel(), []),
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
        (HelpModel(), [1, 2]),
        (CopyrightModel(), [1]),
        (CreditsModel(), [1]),
        (LicenseModel(), [1]),
    ],
)
def test_interactive_output_builtins_reject_excess_positional_arguments(
    model: FunctionModel, args: list[StackValue]
) -> None:
    """Interactive display builtins reject positional forms CPython rejects."""
    result = model.apply(args, {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    "model",
    [
        HelpModel(),
        CopyrightModel(),
        CreditsModel(),
        LicenseModel(),
    ],
)
def test_interactive_output_builtins_reject_keywords(model: FunctionModel) -> None:
    """Interactive display builtins reject keyword calls like CPython."""
    effect = model.apply([], {"x": 1}, _state()).side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_input_rejects_extra_positional_or_keyword_arguments() -> None:
    """input() only permits its optional positional prompt argument."""
    for result in (
        InputModel().apply(["a", "b"], {}, _state()),
        InputModel().apply([], {"prompt": "a"}, _state()),
    ):
        raised = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(raised)
        assert raised["exception_type"] == "TypeError"


def test_breakpoint_declares_configurable_hook_as_unsupported() -> None:
    """breakpoint() cannot silently discard arbitrary configured hook behavior."""
    result = BreakpointModel().apply(["header"], {"verbose": True}, _state())

    assert result.side_effects.get("io") is True
    assert len(result.degradations) == 1
    assert result.degradations[0].label == "builtin_breakpoint_hook_unsupported"
    assert result.degradations[0].kind == "unsupported"


def test_required_keyword_forms_remain_supported() -> None:
    """Required keyword forms accepted by CPython are not rejected as arity errors."""
    results = [
        OpenModel().apply([], {"file": "report.txt"}, _state()),
        CompileModel().apply([], {"source": "1", "filename": "<test>", "mode": "eval"}, _state()),
        ImportModel().apply([], {"name": "math"}, _state()),
        EvalModel().apply(["1"], {"globals": {}}, _state()),
        ExecModel().apply(["x = 1"], {"closure": None}, _state()),
    ]
    assert all("raised_exception" not in result.side_effects for result in results)


def test_environment_facing_builtins_declare_skipped_semantics() -> None:
    """Environment and dynamic-code abstractions cannot report silent success."""
    results = [
        OpenModel().apply(["report.txt"], {}, _state()),
        CompileModel().apply(["1", "<test>", "eval"], {}, _state()),
        ImportModel().apply(["math"], {}, _state()),
        EvalModel().apply(["1"], {}, _state()),
        ExecModel().apply(["x = 1"], {}, _state()),
    ]

    assert all(result.degradations for result in results)
    assert {degradation.kind for result in results for degradation in result.degradations} == {
        "unknown",
        "unsupported",
    }


def test_print_records_io_and_only_degrades_custom_file_hooks() -> None:
    """Default output is observational; custom file protocols remain unsupported."""
    custom_file, _constraint = SymbolicValue.symbolic("custom_print_file")
    default_result = PrintModel().apply(["value"], {}, _state())
    custom_result = PrintModel().apply(["value"], {"file": custom_file}, _state())

    assert default_result.side_effects.get("io") is True
    assert default_result.degradations == ()
    assert custom_result.side_effects.get("io") is True
    assert custom_result.degradations[0].label == (
        "builtin_print_custom_file_semantics_unsupported"
    )


@pytest.mark.parametrize("model", [BytesModel(), BytearrayModel()])
def test_binary_constructors_honor_named_source_length(model: FunctionModel) -> None:
    kwargs: dict[str, StackValue] = {"source": b"ab"}
    result = model.apply([], kwargs, _state())

    assert isinstance(result.value, SymbolicList)
    assert "raised_exception" not in result.side_effects
    solver = z3.Solver()
    solver.add(*result.constraints, result.value.z3_len != 2)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("model", [BytesModel(), BytearrayModel()])
def test_binary_constructors_reject_invalid_keyword_binding(model: FunctionModel) -> None:
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([], {"encoding": "utf-8"}),
        ([b"a"], {"source": b"a"}),
        (["a", "utf-8"], {"encoding": "utf-8"}),
        ([], {"unexpected": b"a"}),
    ]

    for args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


_DYNAMIC_INVALID_CALLS: list[
    tuple[FunctionModel, list[tuple[list[StackValue], dict[str, StackValue]]]]
] = [
    (
        OpenModel(),
        [(["x"], {"file": "x"}), ([], {"unexpected": "x"}), (["x"] * 9, {})],
    ),
    (
        CompileModel(),
        [(["1"], {"source": "1"}), ([], {"unexpected": "x"}), (["1"] * 7, {})],
    ),
    (
        ImportModel(),
        [(["math"], {"name": "math"}), ([], {"unexpected": "x"}), (["math"] * 6, {})],
    ),
    (
        EvalModel(),
        [([], {"source": "1"}), (["1", {}, {}, None], {}), (["1", {}], {"globals": {}})],
    ),
    (
        ExecModel(),
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
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_compile_keyword_symbolic_source_remains_critical_sink() -> None:
    kwargs: dict[str, StackValue] = {
        "source": SymbolicString.from_const("x + 1"),
        "filename": "<test>",
        "mode": "eval",
    }
    result = CompileModel().apply([], kwargs, _state())
    sink_event = result.side_effects.get("sink_event")

    assert SideEffects.is_sink_event(sink_event)
    assert sink_event["severity"] == "critical"


def test_property_accepts_named_descriptor_fields() -> None:
    kwargs: dict[str, StackValue] = {"fget": None, "doc": "value documentation"}
    result = PropertyModel().apply([], kwargs, _state())

    assert "raised_exception" not in result.side_effects


def test_property_rejects_duplicate_or_unknown_fields() -> None:
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([None], {"fget": None}),
        ([], {"unknown": None}),
        ([None, None, None, None, None], {}),
    ]

    for args, kwargs in invalid_calls:
        effect = PropertyModel().apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_pow_and_round_accept_named_parameters() -> None:
    pow_kwargs: dict[str, StackValue] = {"base": 2, "exp": 5}
    round_kwargs: dict[str, StackValue] = {"number": 3.14159, "ndigits": 2}
    pow_result = PowModel().apply([], pow_kwargs, _state())
    round_result = RoundModel().apply([], round_kwargs, _state())

    assert isinstance(pow_result.value, SymbolicValue)
    assert pow_result.value.value == 32
    assert round_result.value == 3.14


def test_pow_and_round_concrete_failures_are_modeled() -> None:
    invalid_mod = PowModel().apply([2, 3, 1.5], {}, _state())
    zero_power = PowModel().apply([0, -1], {}, _state())
    zero_modulus = PowModel().apply([2, -1, 0], {}, _state())
    invalid_ndigits = RoundModel().apply([1.5, 1.0], {}, _state())
    invalid_number = RoundModel().apply(["1.5"], {}, _state())
    invalid_pow_operands = [
        PowModel().apply([None, 2], {}, _state()),
        PowModel().apply([2, []], {}, _state()),
    ]

    expected = [
        (invalid_mod, "TypeError"),
        (zero_power, "ZeroDivisionError"),
        (zero_modulus, "ValueError"),
        (invalid_ndigits, "TypeError"),
        (invalid_number, "TypeError"),
    ]
    for result, exception_type in expected:
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == exception_type
    for result in invalid_pow_operands:
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_pow_and_round_reject_invalid_keyword_binding() -> None:
    invalid_calls: list[tuple[FunctionModel, list[StackValue], dict[str, StackValue]]] = [
        (PowModel(), [2], {"base": 2, "exp": 5}),
        (PowModel(), [], {"base": 2}),
        (RoundModel(), [3.1], {"number": 3.1}),
        (RoundModel(), [], {"ndigits": 2}),
    ]

    for model, args, kwargs in invalid_calls:
        effect = model.apply(args, kwargs, _state()).side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"
