import time
from collections.abc import Callable, MutableMapping
from typing import cast

import z3
from pytest import MonkeyPatch

import pysymex._internal.analysis.detectors.feasibility as feasibility_mod
import pysymex._internal.analysis.evidence.cache as evidence_cache_mod
import pysymex._internal.analysis.evidence.integers as integer_evidence_mod
from pysymex._internal.analysis.detectors.feasibility import (
    detector_witness_model,
    get_model_if_satisfiable_result,
    hard_theory_witness_model,
)
from pysymex._internal.analysis.evidence.floats import zero_float_witness_model
from pysymex._internal.analysis.evidence.integers import integer_witness_model
from pysymex._internal.analysis.evidence.result import FeasibilityModelStatus
from pysymex._internal.analysis.evidence.strings import (
    string_integer_context_truth_value,
    string_integer_witness_model,
)
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.solver.engine.results import SolverResult


def test_string_integer_context_truth_value_maps_ord_variables_from_context() -> None:
    """Scheduling hints may use context to map generated ord variables by stable order."""
    first = z3.Int("ord_20_65541_int")
    second = z3.Int("ord_20_65543_int")
    text = z3.String("license_key_str")

    result = string_integer_context_truth_value(
        [
            z3.Length(text) == 16,
            first == z3.StrToCode(z3.SubString(text, 0, 1)),
            second == z3.StrToCode(z3.SubString(text, 1, 1)),
        ],
        first % 2 == 0,
    )

    assert result is True


def test_string_integer_context_truth_value_returns_none_without_witness_terms() -> None:
    """Ordinary arithmetic branches keep the existing deterministic truth order."""
    value = z3.Int("plain_branch_x")

    assert string_integer_context_truth_value([], value > 0) is None
    assert string_integer_context_truth_value([], value == 1) is None


def test_get_model_if_satisfiable_result_marks_sat_callback_failure_inconclusive() -> None:
    """Structured detector feasibility preserves callback failures."""

    def raising_sat_callback(_constraints: list[z3.BoolRef]) -> bool:
        raise z3.Z3Exception("forced detector SAT callback failure")

    result = get_model_if_satisfiable_result([z3.BoolVal(True)], raising_sat_callback)

    assert result.status is FeasibilityModelStatus.INCONCLUSIVE
    assert result.is_inconclusive is True
    assert result.model is None
    assert result.reason == "sat_callback_failed"


def test_get_model_if_satisfiable_result_marks_callback_false_as_no_sat_evidence() -> None:
    """Callback-false results remain distinct from callback/model failures."""

    result = get_model_if_satisfiable_result(
        [z3.BoolVal(True)],
        lambda _constraints: False,
    )

    assert result.status is FeasibilityModelStatus.NO_SAT_EVIDENCE
    assert result.is_sat is False
    assert result.model is None
    assert result.reason == "sat_callback_returned_false"


def test_get_model_if_satisfiable_result_marks_model_callback_failure_inconclusive() -> None:
    """Structured detector feasibility preserves model callback failures."""
    x = z3.Int("detector_feasibility_result_model_callback_failure_x")

    def raising_model_callback(_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        raise z3.Z3Exception("forced detector model callback failure")

    result = get_model_if_satisfiable_result(
        [x == 4096],
        lambda _constraints: True,
        raising_model_callback,
        allow_witness_model=False,
    )

    assert result.status is FeasibilityModelStatus.INCONCLUSIVE
    assert result.model is None
    assert result.reason == "model_callback_failed"


def test_get_model_if_satisfiable_result_marks_missing_model_inconclusive() -> None:
    """SAT callback evidence without a model is not a reportable bug witness."""
    x = z3.Int("detector_feasibility_missing_model_x")

    result = get_model_if_satisfiable_result(
        [x == 4096],
        lambda _constraints: True,
        lambda _constraints: None,
        allow_witness_model=False,
    )

    assert result.status is FeasibilityModelStatus.INCONCLUSIVE
    assert result.model is None
    assert result.reason == "sat_without_model"


def test_get_model_if_satisfiable_result_uses_default_structured_model_sat() -> None:
    """The default model path consumes core SolverResult evidence."""
    x = z3.Int("detector_feasibility_default_sat_x")

    result = get_model_if_satisfiable_result(
        [x == 1],
        lambda _constraints: True,
    )

    assert result.status is FeasibilityModelStatus.SAT
    assert result.model is not None
    assert result.reason is None


def test_get_model_if_satisfiable_result_uses_default_structured_model_unsat() -> None:
    """Default core model evidence can separate UNSAT from generic missing models."""
    x = z3.Int("detector_feasibility_default_unsat_x")

    result = get_model_if_satisfiable_result(
        [x == 1, x == 2],
        lambda _constraints: True,
    )

    assert result.status is FeasibilityModelStatus.NO_SAT_EVIDENCE
    assert result.model is None
    assert result.reason == "model_result_unsat"


def test_get_model_if_satisfiable_result_uses_default_structured_model_unknown() -> None:
    """Default core model evidence can separate UNKNOWN from generic missing models."""
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    flag = z3.Bool("detector_feasibility_default_unknown_flag")
    token = SolverContext.active.set(solver)
    try:
        result = get_model_if_satisfiable_result(
            [flag],
            lambda _constraints: True,
        )
    finally:
        SolverContext.active.reset(token)

    assert result.status is FeasibilityModelStatus.INCONCLUSIVE
    assert result.model is None
    assert result.reason == "model_result_unknown"


def test_get_model_if_satisfiable_result_uses_detached_model_after_active_unknown() -> None:
    """A fresh solver may provide SAT evidence when the active model query is unknown."""

    class ActiveUnknownModelSolver(IncrementalSolver):
        def __init__(self) -> None:
            super().__init__(timeout_ms=5000)

        def check_sat_cached(
            self,
            constraints: list[z3.BoolRef],
            known_sat_prefix_len: int | None = None,
        ) -> SolverResult:
            _ = constraints
            _ = known_sat_prefix_len
            return SolverResult.unknown()

        def _effective_timeout_ms(self) -> int:
            return 5000

    count = z3.Int("count_detector_feasibility_detached_retry_int")
    bin_length = z3.Int("bin_detector_feasibility_detached_retry_len")
    token = SolverContext.active.set(ActiveUnknownModelSolver())
    try:
        result = get_model_if_satisfiable_result(
            [bin_length >= 3, count == 0],
            lambda _constraints: True,
        )
    finally:
        SolverContext.active.reset(token)

    assert result.status is FeasibilityModelStatus.SAT
    assert result.model is not None
    assert result.reason is None


def test_integer_witness_model_returns_model_for_small_int_assignment() -> None:
    """Concrete substitution can prove simple integer detector queries SAT."""
    x = z3.Int("detector_integer_witness_x")
    y = z3.Int("detector_integer_witness_y")

    model = integer_witness_model([x == 0, y == 4, x + y == 4])

    assert model is not None
    assert model.eval(x).as_long() == 0
    assert model.eval(y).as_long() == 4


def test_integer_witness_model_accepts_alternating_two_bit_guard_pattern() -> None:
    """Small parity/bit guards can be witnessed without an expensive full solve."""
    a = z3.Int("detector_alternating_bit_guard_a")
    b = z3.Int("detector_alternating_bit_guard_b")
    c = z3.Int("detector_alternating_bit_guard_c")
    d = z3.Int("detector_alternating_bit_guard_d")
    e = z3.Int("detector_alternating_bit_guard_e")
    f = z3.Int("detector_alternating_bit_guard_f")
    low_bits = z3.BV2Int(z3.Extract(1, 0, z3.Int2BV(b, 64) ^ z3.Int2BV(e, 64)))
    constraints = [
        b != c,
        a + c == d - f,
        low_bits == 2,
        z3.BV2Int(z3.Extract(1, 0, z3.Int2BV(f, 64))) == 3,
    ]

    model = integer_witness_model(constraints)

    assert model is not None
    assert z3.is_true(model.eval(z3.And(*constraints), model_completion=True))


def test_integer_witness_model_returns_model_for_generated_four_int_assignment() -> None:
    """Generated sequence assignments cover bounded four-variable detector queries."""
    a = z3.Int("detector_integer_witness_seed_a")
    b = z3.Int("detector_integer_witness_seed_b")
    c = z3.Int("detector_integer_witness_seed_c")
    d = z3.Int("detector_integer_witness_seed_d")

    model = integer_witness_model(
        [
            a == 0,
            b == 1,
            c == 2,
            d == 3,
            a + b + c + d == 6,
        ]
    )

    assert model is not None
    assert model.eval(a).as_long() == 0
    assert model.eval(b).as_long() == 1
    assert model.eval(c).as_long() == 2
    assert model.eval(d).as_long() == 3


def test_integer_witness_model_returns_model_for_repeated_five_int_assignment() -> None:
    """Generated repeated assignments cover multi-variable signed integer witnesses."""
    a = z3.Int("detector_integer_witness_seed_five_a")
    b = z3.Int("detector_integer_witness_seed_five_b")
    c = z3.Int("detector_integer_witness_seed_five_c")
    d = z3.Int("detector_integer_witness_seed_five_d")
    e = z3.Int("detector_integer_witness_seed_five_e")

    model = integer_witness_model(
        [
            a == -4,
            b == -4,
            c == -4,
            d == -4,
            e == -4,
            a + b + c + d + e == -20,
        ]
    )

    assert model is not None
    assert model.eval(a).as_long() == -4
    assert model.eval(b).as_long() == -4
    assert model.eval(c).as_long() == -4
    assert model.eval(d).as_long() == -4
    assert model.eval(e).as_long() == -4


def test_integer_witness_model_returns_model_for_generated_six_int_assignment() -> None:
    """Generated sequence assignments cover six-variable detector queries."""
    a = z3.Int("detector_integer_witness_seed_six_a")
    b = z3.Int("detector_integer_witness_seed_six_b")
    bit_count = z3.Int("detector_integer_witness_seed_six_bit_count")
    c = z3.Int("detector_integer_witness_seed_six_c")
    d = z3.Int("detector_integer_witness_seed_six_d")
    e = z3.Int("detector_integer_witness_seed_six_e")

    model = integer_witness_model(
        [
            a == 0,
            b == 1,
            bit_count == 2,
            c == 3,
            d == 4,
            e == 5,
            a + b + bit_count + c + d + e == 15,
        ]
    )

    assert model is not None
    assert model.eval(a).as_long() == 0
    assert model.eval(b).as_long() == 1
    assert model.eval(bit_count).as_long() == 2
    assert model.eval(c).as_long() == 3
    assert model.eval(d).as_long() == 4
    assert model.eval(e).as_long() == 5


def test_integer_witness_model_rejects_formula_without_integer_solution() -> None:
    """Bounded witness search must not infer SAT without a verified assignment."""
    x = z3.Int("detector_integer_witness_capped_x")

    assert integer_witness_model([x * x == 17]) is None


def test_integer_witness_model_skips_search_for_simplified_false_formula(
    monkeypatch: MonkeyPatch,
) -> None:
    """Contradictory detector formulas should not pay the assignment-search cost."""
    x = z3.Int("detector_integer_witness_simplified_false_x")

    def fail_assignment_search(
        _formula: z3.BoolRef,
        _variables: list[z3.ArithRef],
        _values: tuple[int, ...],
    ) -> z3.ModelRef | None:
        raise AssertionError("assignment search should not run for simplified false formulas")

    monkeypatch.setattr(
        integer_evidence_mod,
        "_verified_integer_assignment_model",
        fail_assignment_search,
    )

    assert integer_witness_model([x == 1, z3.Not(x == 1)]) is None


def test_integer_witness_model_returns_none_without_verified_assignment() -> None:
    """Witness enumeration must not infer SAT when no candidate proves all constraints."""
    x = z3.Int("detector_integer_witness_out_of_range_x")

    assert integer_witness_model([x > 0, x < 0]) is None


def test_string_integer_witness_model_returns_model_for_prefix_assignment() -> None:
    """Concrete string and integer substitution can prove prefix detector queries SAT."""
    text = z3.String("detector_text_1_str")
    text_type_flags = [
        z3.Bool("detector_text_1_is_int"),
        z3.Bool("detector_text_1_is_bool"),
        z3.Bool("detector_text_1_is_str"),
        z3.Bool("detector_text_1_is_path"),
        z3.Bool("detector_text_1_is_obj"),
        z3.Bool("detector_text_1_is_none"),
        z3.Bool("detector_text_1_is_float"),
        z3.Bool("detector_text_1_is_list"),
        z3.Bool("detector_text_1_is_dict"),
    ]
    len_text = z3.Int("len_text_int")
    salt = z3.Int("salt_int")

    model = string_integer_witness_model(
        [
            z3.PbEq([(flag, 1) for flag in text_type_flags], 1),
            z3.Bool("detector_text_1_is_str"),
            len_text == z3.Length(text),
            z3.PrefixOf(z3.StringVal("ab"), text),
            z3.SubString(text, 0, 1) == z3.StringVal("a"),
            z3.SubString(text, 1, 1) == z3.StringVal("b"),
            len_text == 2,
            salt == 2,
        ]
    )

    assert model is not None
    assert model.eval(text).as_string() == "ab"
    assert model.eval(len_text).as_long() == 2
    assert model.eval(salt).as_long() == 2


def test_string_integer_witness_model_returns_model_for_ord_state_assignment() -> None:
    """A validated string/ord seed can prove codepoint-heavy queries SAT."""
    text = z3.String("detector_license_key_str")
    text_type_flags = [
        z3.Bool("detector_license_key_is_int"),
        z3.Bool("detector_license_key_is_bool"),
        z3.Bool("detector_license_key_is_str"),
        z3.Bool("detector_license_key_is_path"),
        z3.Bool("detector_license_key_is_obj"),
        z3.Bool("detector_license_key_is_none"),
        z3.Bool("detector_license_key_is_float"),
        z3.Bool("detector_license_key_is_list"),
        z3.Bool("detector_license_key_is_dict"),
    ]
    len_text = z3.Int("len_license_key_int")
    ord_values = [z3.Int(f"ord_19_6554{index}_int") for index in range(1, 10, 2)]
    witness_text = "\x00\x04\x04\x04\x88"

    model = string_integer_witness_model(
        [
            z3.PbEq([(flag, 1) for flag in text_type_flags], 1),
            z3.Bool("detector_license_key_is_str"),
            len_text == z3.Length(text),
            len_text == 5,
            *[
                z3.SubString(text, index, 1) == z3.StringVal(character)
                for index, character in enumerate(witness_text)
            ],
            *[
                value == z3.StrToCode(z3.SubString(text, index, 1))
                for index, value in enumerate(ord_values)
            ],
            (ord_values[0] * 65536 + ord_values[2] * 256 + ord_values[4]) % 16777216 == 0x000488,
            ord_values[1] == ord_values[3],
            ord_values[1] - ord_values[3] == 0,
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(model.eval(text) == z3.StringVal(witness_text)))
    assert model.eval(len_text).as_long() == 5
    assert [model.eval(value).as_long() for value in ord_values] == [
        ord(character) for character in witness_text
    ]


def test_string_integer_witness_model_returns_model_for_short_license_ord_seeds() -> None:
    """Short license-string seeds cover reduced hash bridge detector queries."""
    cases = [("\x00\x04\x04", 0x0004), ("\x00\x04\x04\x04", 0x000404)]

    for witness_text, expected_signature in cases:
        text = z3.String(f"detector_short_license_key_{len(witness_text)}_str")
        len_text = z3.Int(f"len_short_license_key_{len(witness_text)}_int")
        ord_values = [
            z3.Int(f"ord_20_{len(witness_text)}_{index}_int") for index in range(len(witness_text))
        ]
        if len(witness_text) == 3:
            signature = (ord_values[0] * 256 + ord_values[2]) % 65536
        else:
            signature = (ord_values[0] * 65536 + ord_values[2] * 256 + ord_values[3]) % 16777216

        model = string_integer_witness_model(
            [
                len_text == z3.Length(text),
                len_text == len(witness_text),
                *[
                    z3.SubString(text, index, 1) == z3.StringVal(character)
                    for index, character in enumerate(witness_text)
                ],
                *[
                    value == z3.StrToCode(z3.SubString(text, index, 1))
                    for index, value in enumerate(ord_values)
                ],
                signature == expected_signature,
            ]
        )

        assert model is not None
        assert z3.is_true(simplify_expr(model.eval(text) == z3.StringVal(witness_text)))
        assert model.eval(len_text).as_long() == len(witness_text)
        assert [model.eval(value).as_long() for value in ord_values] == [
            ord(character) for character in witness_text
        ]


def test_string_integer_witness_model_returns_model_for_bin_count_bridge() -> None:
    """Two-string witnesses cover license keys plus modeled bin().count() text."""
    key_text = z3.String("key_65536_str")
    bin_text = z3.String("bin_107_65557_str")
    key_type_flags = [
        z3.Bool("key_65536_is_int"),
        z3.Bool("key_65536_is_bool"),
        z3.Bool("key_65536_is_str"),
        z3.Bool("key_65536_is_path"),
        z3.Bool("key_65536_is_obj"),
        z3.Bool("key_65536_is_none"),
        z3.Bool("key_65536_is_float"),
        z3.Bool("key_65536_is_list"),
        z3.Bool("key_65536_is_dict"),
    ]
    bin_type_flags = [
        z3.Bool("bin_107_65557_is_int"),
        z3.Bool("bin_107_65557_is_bool"),
        z3.Bool("bin_107_65557_is_str"),
        z3.Bool("bin_107_65557_is_path"),
        z3.Bool("bin_107_65557_is_obj"),
        z3.Bool("bin_107_65557_is_none"),
        z3.Bool("bin_107_65557_is_float"),
        z3.Bool("bin_107_65557_is_list"),
        z3.Bool("bin_107_65557_is_dict"),
    ]
    len_key = z3.Int("len_key_int")
    count = z3.Int("count_110_int")
    ord_values = [z3.Int(f"ord_19_6554{index}_int") for index in range(1, 10, 2)]
    witness_text = "\x00\x04\x04\x04\x88"
    witness_bin = "0b111111111111111"

    model = string_integer_witness_model(
        [
            z3.PbEq([(flag, 1) for flag in key_type_flags], 1),
            z3.Bool("key_65536_is_str"),
            z3.PbEq([(flag, 1) for flag in bin_type_flags], 1),
            z3.Bool("bin_107_65557_is_str"),
            len_key == z3.Length(key_text),
            len_key == len(witness_text),
            bin_text == z3.StringVal(witness_bin),
            count == 15,
            *[
                z3.SubString(key_text, index, 1) == z3.StringVal(character)
                for index, character in enumerate(witness_text)
            ],
            *[
                value == z3.StrToCode(z3.SubString(key_text, index, 1))
                for index, value in enumerate(ord_values)
            ],
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(model.eval(key_text) == z3.StringVal(witness_text)))
    assert z3.is_true(simplify_expr(model.eval(bin_text) == z3.StringVal(witness_bin)))
    assert model.eval(count).as_long() == 15
    assert [model.eval(value).as_long() for value in ord_values] == [
        ord(character) for character in witness_text
    ]


def test_string_integer_witness_model_derives_helper_ints_for_long_license_seed() -> None:
    """Long string witnesses can derive generated helper integers from equalities."""
    key_text = z3.String("key_str_65536_str")
    bin_text = z3.String("bin_116_65590_str")
    len_key = z3.Int("len_key_str_int")
    count = z3.Int("count_119_int")
    helper_sum = z3.Int("sum_136_int")
    ord_values = [z3.Int(f"ord_20_655{41 + 2 * index}_int") for index in range(16)]
    witness_text = bytes(
        (149, 68, 82, 152, 237, 45, 44, 113, 195, 2, 146, 214, 10, 73, 236, 91)
    ).decode("latin-1")

    model = string_integer_witness_model(
        [
            len_key == z3.Length(key_text),
            len_key == len(witness_text),
            bin_text == z3.StringVal("0b1111111111111"),
            count == 13,
            *[
                z3.SubString(key_text, index, 1) == z3.StringVal(character)
                for index, character in enumerate(witness_text)
            ],
            *[
                value == z3.StrToCode(z3.SubString(key_text, index, 1))
                for index, value in enumerate(ord_values)
            ],
            helper_sum == sum(ord_values),
            helper_sum - sum(ord(character) for character in witness_text) == 0,
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(model.eval(key_text) == z3.StringVal(witness_text)))
    assert model.eval(helper_sum).as_long() == sum(ord(character) for character in witness_text)


def test_string_integer_witness_model_returns_model_for_rfind_missing_seed() -> None:
    """Concrete missing-substring seeds prove rfind -1 divisor queries SAT."""
    text = z3.String("detector_rfind_text_str")
    text_type_flags = [
        z3.Bool("detector_rfind_text_is_int"),
        z3.Bool("detector_rfind_text_is_bool"),
        z3.Bool("detector_rfind_text_is_str"),
        z3.Bool("detector_rfind_text_is_path"),
        z3.Bool("detector_rfind_text_is_obj"),
        z3.Bool("detector_rfind_text_is_none"),
        z3.Bool("detector_rfind_text_is_float"),
        z3.Bool("detector_rfind_text_is_list"),
        z3.Bool("detector_rfind_text_is_dict"),
    ]
    len_text = z3.Int("len_detector_rfind_text_int")
    index = z3.Int("rfind_20_int")
    salt = z3.Int("salt_int")

    model = string_integer_witness_model(
        [
            z3.PbEq([(flag, 1) for flag in text_type_flags], 1),
            z3.Bool("detector_rfind_text_is_str"),
            len_text == z3.Length(text),
            len_text == 3,
            text == z3.StringVal("bbb"),
            z3.Not(z3.Contains(text, z3.StringVal("a"))),
            index == -1,
            salt == 0,
            index + 1 == 0,
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(model.eval(text) == z3.StringVal("bbb")))
    assert model.eval(index).as_long() == -1
    assert model.eval(salt).as_long() == 0


def test_detector_witness_model_assigns_integer_type_flags_without_string_slot() -> None:
    """Simplified detector formulas may retain integer type flags after dropping string slots."""
    text = z3.String("detector_rfind_simplified_text_str")
    text_type_flags = [
        z3.Bool("detector_rfind_simplified_text_is_int"),
        z3.Bool("detector_rfind_simplified_text_is_bool"),
        z3.Bool("detector_rfind_simplified_text_is_str"),
        z3.Bool("detector_rfind_simplified_text_is_path"),
        z3.Bool("detector_rfind_simplified_text_is_obj"),
        z3.Bool("detector_rfind_simplified_text_is_none"),
        z3.Bool("detector_rfind_simplified_text_is_float"),
        z3.Bool("detector_rfind_simplified_text_is_list"),
        z3.Bool("detector_rfind_simplified_text_is_dict"),
    ]
    index = z3.Int("rfind_simplified_20_int")
    rfind_float = z3.FP("rfind_simplified_20_float", z3.Float64())
    rfind_type_flags = [
        z3.Bool("rfind_simplified_20_is_int"),
        z3.Bool("rfind_simplified_20_is_bool"),
        z3.Bool("rfind_simplified_20_is_str"),
        z3.Bool("rfind_simplified_20_is_path"),
        z3.Bool("rfind_simplified_20_is_obj"),
        z3.Bool("rfind_simplified_20_is_none"),
        z3.Bool("rfind_simplified_20_is_float"),
        z3.Bool("rfind_simplified_20_is_list"),
        z3.Bool("rfind_simplified_20_is_dict"),
    ]
    salt = z3.Int("salt_int")

    model = detector_witness_model(
        [
            z3.PbEq([(flag, 1) for flag in text_type_flags], 1),
            z3.Bool("detector_rfind_simplified_text_is_str"),
            z3.PbEq([(flag, 1) for flag in rfind_type_flags], 1),
            z3.Bool("rfind_simplified_20_is_int"),
            index >= -1,
            z3.Implies(z3.Not(z3.Contains(text, z3.StringVal("a"))), index == -1),
            z3.Implies(index == -1, z3.Not(z3.SuffixOf(z3.StringVal("a"), text))),
            salt % 2 == 0,
            z3.Or(
                z3.And(z3.Bool("rfind_simplified_20_is_int"), index == -1),
                z3.And(z3.Bool("rfind_simplified_20_is_float"), z3.fpIsZero(rfind_float)),
            ),
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(z3.Not(z3.Contains(model.eval(text), z3.StringVal("a")))))
    assert model.eval(index).as_long() == -1
    assert model.eval(salt).as_long() == 0


def test_detector_witness_model_returns_integer_witness() -> None:
    x = z3.Int("detector_combined_integer_witness_x")

    model = detector_witness_model([x == 4])

    assert model is not None
    assert model.eval(x).as_long() == 4


def test_detector_witness_model_solves_boolean_residue_after_integer_assignment() -> None:
    """Integer substitution may leave only builtin-truth aggregate Booleans."""
    a = z3.Int("detector_generator_any_a")
    b = z3.Int("detector_generator_any_b")
    c = z3.Int("detector_generator_any_c")
    any_result = z3.Bool("detector_generator_any_result")
    xor_parity = (z3.Int2BV(a, 64) ^ z3.Int2BV(b, 64) ^ z3.Int2BV(c, 64)) & z3.BitVecVal(1, 64)

    model = detector_witness_model(
        [
            xor_parity == z3.BitVecVal(1, 64),
            any_result
            == z3.Or(
                a - b == 0,
                b - c == 0,
                c - a == 0,
            ),
            any_result,
            a == b,
            c % 2 == 1,
            a - b == 0,
        ]
    )

    assert model is not None
    assert model.eval(a).as_long() == model.eval(b).as_long()
    assert model.eval(c).as_long() % 2 == 1
    assert z3.is_true(model.eval(any_result, model_completion=True))


def test_detector_witness_model_returns_zero_float_witness() -> None:
    x = z3.FP("detector_combined_float_witness_x", z3.Float64())

    model = detector_witness_model([x == z3.FPVal(0.0, z3.Float64())])

    assert model is not None
    assert z3.is_true(
        simplify_expr(model.eval(x, model_completion=True) == z3.FPVal(0.0, z3.Float64()))
    )


def test_detector_witness_model_returns_string_integer_witness() -> None:
    text = z3.String("detector_combined_text_str")
    length = z3.Int("len_detector_combined_text_int")

    model = detector_witness_model(
        [
            length == z3.Length(text),
            length == 3,
            text == z3.StringVal("bbb"),
            z3.Not(z3.Contains(text, z3.StringVal("a"))),
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(model.eval(text) == z3.StringVal("bbb")))


def test_detector_witness_model_returns_zero_numeric_string_witness() -> None:
    """Concrete numeric-string substitution proves regex/int detector queries SAT."""
    text = z3.String("detector_combined_zero_text_str")
    parsed = z3.Int("int_detector_combined_zero_text_int")

    model = detector_witness_model(
        [
            z3.InRe(text, z3.Plus(z3.Re("0"))),
            parsed == z3.StrToInt(text),
            parsed == 0,
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(model.eval(text) == z3.StringVal("0")))
    assert model.eval(parsed).as_long() == 0


def test_witness_constants_reuses_same_live_formula_collection(
    monkeypatch: MonkeyPatch,
) -> None:
    """Repeated access to one live formula should not repeat AST collection."""
    x = z3.Int("detector_combined_constant_cache_x")
    formula = x == 4096
    calls = 0
    original_collect = cast(
        "Callable[[z3.ExprRef], object]",
        evidence_cache_mod.collect_witness_constants,
    )
    cache = cast(
        "MutableMapping[object, object]",
        getattr(evidence_cache_mod, "_WITNESS_CONSTANTS_CACHE"),
    )
    cache.clear()

    def counting_collect(formula: z3.ExprRef) -> object:
        nonlocal calls
        calls += 1
        return original_collect(formula)

    monkeypatch.setattr(evidence_cache_mod, "collect_witness_constants", counting_collect)

    assert evidence_cache_mod.witness_constants(formula) is not None
    assert evidence_cache_mod.witness_constants(formula) is not None

    assert calls == 1


def test_witness_constants_reuses_wrapper_equivalent_formula_collection(
    monkeypatch: MonkeyPatch,
) -> None:
    """Different Python wrappers for one Z3 AST should share variable collection."""
    x = z3.Int("detector_combined_wrapper_cache_x")
    formula = x == 4096
    calls = 0
    original_collect = cast(
        "Callable[[z3.ExprRef], object]",
        evidence_cache_mod.collect_witness_constants,
    )
    cache = cast(
        "MutableMapping[object, object]",
        getattr(evidence_cache_mod, "_WITNESS_CONSTANTS_CACHE"),
    )
    cache.clear()

    def counting_collect(formula: z3.ExprRef) -> object:
        nonlocal calls
        calls += 1
        return original_collect(formula)

    monkeypatch.setattr(evidence_cache_mod, "collect_witness_constants", counting_collect)
    as_ast = cast("Callable[[], object]", getattr(formula, "as_ast"))
    bool_ref = cast("Callable[[object, object], object]", z3.BoolRef)
    equivalent_wrapper = cast("z3.BoolRef", bool_ref(as_ast(), formula.ctx))

    assert evidence_cache_mod.witness_constants(formula) is not None
    assert evidence_cache_mod.witness_constants(equivalent_wrapper) is not None

    assert calls == 1


def test_string_integer_witness_collects_variables_once(monkeypatch: MonkeyPatch) -> None:
    """A string witness probe should discover all variable families in one AST walk."""
    text = z3.String("detector_single_pass_text_str")
    length = z3.Int("len_detector_single_pass_text_int")
    text_is_str = z3.Bool("detector_single_pass_text_is_str")
    calls = 0
    original_collect = cast(
        "Callable[[z3.ExprRef], object]",
        evidence_cache_mod.collect_witness_constants,
    )
    cache = cast(
        "MutableMapping[object, object]",
        getattr(evidence_cache_mod, "_WITNESS_CONSTANTS_CACHE"),
    )
    cache.clear()

    def counting_collect(formula: z3.ExprRef) -> object:
        nonlocal calls
        calls += 1
        return original_collect(formula)

    monkeypatch.setattr(evidence_cache_mod, "collect_witness_constants", counting_collect)

    model = string_integer_witness_model(
        [
            text == z3.StringVal("bbb"),
            length == z3.Length(text),
            length == 3,
            text_is_str,
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(model.eval(text) == z3.StringVal("bbb")))
    assert calls == 1


def test_hard_theory_witness_model_skips_simple_integer_formula() -> None:
    """The pre-solver witness gate should avoid extra work on simple arithmetic."""
    x = z3.Int("detector_hard_witness_simple_x")

    assert hard_theory_witness_model([x == 0]) is None


def test_hard_theory_witness_model_accepts_zero_numeric_string_formula() -> None:
    """Hard string formulas can still be proved SAT before native solving."""
    text = z3.String("detector_hard_witness_zero_text_str")
    parsed = z3.Int("int_detector_hard_witness_zero_text_int")

    model = hard_theory_witness_model(
        [
            z3.InRe(text, z3.Plus(z3.Re("0"))),
            parsed == z3.StrToInt(text),
            parsed == 0,
        ]
    )

    assert model is not None
    assert z3.is_true(simplify_expr(model.eval(text) == z3.StringVal("0")))
    assert model.eval(parsed).as_long() == 0


def test_hard_theory_witness_model_skips_exact_false_conjunction(
    monkeypatch: MonkeyPatch,
) -> None:
    """Exact falsehoods cannot have witnesses, even beside hard string theory."""
    text = z3.String("detector_hard_witness_false_text_str")

    def fail_witness(_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        raise AssertionError("exact false conjunction should skip witness search")

    monkeypatch.setattr(feasibility_mod, "detector_witness_model", fail_witness)

    model = hard_theory_witness_model(
        [
            z3.InRe(text, z3.Plus(z3.Re("0"))),
            z3.BoolVal(False),
        ]
    )

    assert model is None


def test_string_integer_witness_model_rejects_inconsistent_ord_state_assignment() -> None:
    """Ord-seeded string witnesses still require the complete query to simplify true."""
    text = z3.String("detector_inconsistent_license_key_str")
    len_text = z3.Int("len_inconsistent_license_key_int")
    ord_values = [z3.Int(f"ord_19_7554{index}_int") for index in range(1, 10, 2)]
    witness_text = "\x00\x04\x04\x04\x88"

    model = string_integer_witness_model(
        [
            len_text == z3.Length(text),
            len_text == 5,
            *[
                z3.SubString(text, index, 1) == z3.StringVal(character)
                for index, character in enumerate(witness_text)
            ],
            *[
                value == z3.StrToCode(z3.SubString(text, index, 1))
                for index, value in enumerate(ord_values)
            ],
            ord_values[1] == ord_values[3],
            ord_values[1] != ord_values[3],
        ]
    )

    assert model is None


def test_get_model_if_satisfiable_result_uses_integer_witness_before_unknown_model() -> None:
    """A concrete integer witness is SAT evidence even when model extraction is unavailable."""
    x = z3.Int("detector_integer_witness_fallback_x")
    constraints = [x == 4]

    result = get_model_if_satisfiable_result(
        constraints,
        lambda _constraints: True,
        lambda _constraints: None,
    )

    assert result.status is FeasibilityModelStatus.SAT
    assert isinstance(result.model, z3.ModelRef)
    assert result.model.eval(x).as_long() == 4


def test_get_model_if_satisfiable_result_uses_hard_witness_after_no_sat_callback() -> None:
    """A verified hard-theory witness can recover SAT evidence from a false callback."""
    text = z3.String("detector_witness_before_callback_text_str")
    parsed = z3.Int("int_detector_witness_before_callback_text_int")

    result = get_model_if_satisfiable_result(
        [
            z3.InRe(text, z3.Plus(z3.Re("0"))),
            parsed == z3.StrToInt(text),
            parsed == 0,
        ],
        lambda _constraints: False,
    )

    assert result.status is FeasibilityModelStatus.SAT
    assert isinstance(result.model, z3.ModelRef)
    assert z3.is_true(simplify_expr(result.model.eval(text) == z3.StringVal("0")))
    assert result.model.eval(parsed).as_long() == 0


def test_get_model_if_satisfiable_result_returns_sat_model_evidence() -> None:
    """Structured detector feasibility returns model-backed SAT evidence."""
    x = z3.Int("detector_feasibility_sat_x")
    constraints = [x == 1]

    def model_callback(model_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        solver = z3.Solver()
        solver.add(*model_constraints)
        if solver.check() != z3.sat:
            return None
        return solver.model()

    result = get_model_if_satisfiable_result(
        constraints,
        lambda _constraints: True,
        model_callback,
    )

    assert result.status is FeasibilityModelStatus.SAT
    assert result.is_sat is True
    assert result.model is not None
    assert result.reason is None


def test_zero_float_witness_model_returns_none_when_witness_solver_fails(
    monkeypatch: MonkeyPatch,
) -> None:
    """Float witness solver failures are inconclusive, not detector crashes."""
    fp_value = z3.FP("detector_witness_failure_fp", z3.Float64())

    class FailingWitnessSolver:
        def add(self, *_constraints: z3.BoolRef) -> None:
            raise z3.Z3Exception("forced float witness add failure")

        def check(self) -> z3.CheckSatResult:
            return z3.sat

        def model(self) -> z3.ModelRef:
            raise AssertionError("model should not be requested after add failure")

    monkeypatch.setattr(z3, "Solver", FailingWitnessSolver)

    assert zero_float_witness_model([fp_value == z3.FPVal(0.0, z3.Float64())]) is None
