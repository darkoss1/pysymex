"""Witness-focused detector feasibility tests for core executor queries."""

from __future__ import annotations

import z3

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.execution.detectors.query.cache.policy import detector_query_is_sat
from pysymex._internal.execution.detectors.unknown import (
    SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS,
)
from pysymex._internal.execution.executors.core import SymbolicExecutor
from tests.unit.execution.executors.core_executor_helpers import UnknownSolver


def _detector_query_is_sat(executor: SymbolicExecutor, constraints: list[z3.BoolRef]) -> bool:
    return detector_query_is_sat(
        session=executor.session,
        solver=executor.solver,
        constraints=constraints,
    )


class TestSymbolicExecutorFeasibilityWitnesses:
    """Detector feasibility cases proven by concrete witness search."""

    def test_detector_feasibility_accepts_concrete_zero_float_witness(self) -> None:
        """A fully validated float-zero assignment proves detector feasibility."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        value = z3.FP("detector_float_zero_x", z3.Float64())

        result = _detector_query_is_sat(
            executor,
            [z3.fpIsZero(z3.fpMul(z3.RNE(), value, value))],
        )

        assert result is True
        assert executor.session.degraded_passes == []
        assert unknown_solver.prefix_args == []

    def test_detector_feasibility_accepts_concrete_integer_witness(self) -> None:
        """A fully validated small-integer assignment proves detector feasibility."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        x = z3.Int("detector_integer_witness_x")
        y = z3.Int("detector_integer_witness_y")

        result = _detector_query_is_sat(executor, [x == 0, y == 4, x + y == 4])

        assert result is True
        assert executor.session.degraded_passes == []
        assert unknown_solver.prefix_args == [None]

    def test_detector_feasibility_accepts_seeded_four_integer_witness(self) -> None:
        """A validated four-variable seed assignment avoids solver UNKNOWN."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        a = z3.Int("detector_seed_integer_witness_a")
        b = z3.Int("detector_seed_integer_witness_b")
        c = z3.Int("detector_seed_integer_witness_c")
        d = z3.Int("detector_seed_integer_witness_d")

        result = _detector_query_is_sat(
            executor,
            [a == 0, b == 4, c == 4, d == 4, a + b + c + d == 12],
        )

        assert result is True
        assert executor.session.degraded_passes == []
        assert unknown_solver.prefix_args == [None]

    def test_detector_feasibility_accepts_seeded_five_integer_witness(self) -> None:
        """A validated five-variable seed assignment avoids solver UNKNOWN."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        a = z3.Int("detector_seed_integer_witness_five_a")
        b = z3.Int("detector_seed_integer_witness_five_b")
        c = z3.Int("detector_seed_integer_witness_five_c")
        d = z3.Int("detector_seed_integer_witness_five_d")
        e = z3.Int("detector_seed_integer_witness_five_e")

        result = _detector_query_is_sat(
            executor,
            [a == 0, b == 4, c == 4, d == 4, e == 136, a + b + c + d + e == 148],
        )

        assert result is True
        assert executor.session.degraded_passes == []
        assert unknown_solver.prefix_args == [None]

    def test_detector_feasibility_accepts_seeded_six_integer_witness(self) -> None:
        """A validated six-variable seed assignment avoids solver UNKNOWN."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        a = z3.Int("detector_seed_integer_witness_six_a")
        b = z3.Int("detector_seed_integer_witness_six_b")
        bit_count = z3.Int("detector_seed_integer_witness_six_bit_count")
        c = z3.Int("detector_seed_integer_witness_six_c")
        d = z3.Int("detector_seed_integer_witness_six_d")
        e = z3.Int("detector_seed_integer_witness_six_e")

        result = _detector_query_is_sat(
            executor,
            [
                a == 0,
                b == 4,
                bit_count == 15,
                c == 4,
                d == 4,
                e == 136,
                a + b + bit_count + c + d + e == 163,
            ],
        )

        assert result is True
        assert executor.session.degraded_passes == []
        assert unknown_solver.prefix_args == [None]

    def test_detector_feasibility_accepts_string_integer_witness(self) -> None:
        """A validated string/int assignment avoids solver UNKNOWN."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        text = z3.String("detector_exec_text_1_str")
        text_type_flags = [
            z3.Bool("detector_exec_text_1_is_int"),
            z3.Bool("detector_exec_text_1_is_bool"),
            z3.Bool("detector_exec_text_1_is_str"),
            z3.Bool("detector_exec_text_1_is_path"),
            z3.Bool("detector_exec_text_1_is_obj"),
            z3.Bool("detector_exec_text_1_is_none"),
            z3.Bool("detector_exec_text_1_is_float"),
            z3.Bool("detector_exec_text_1_is_list"),
            z3.Bool("detector_exec_text_1_is_dict"),
        ]
        len_text = z3.Int("len_text_int")
        salt = z3.Int("salt_int")

        result = _detector_query_is_sat(
            executor,
            [
                z3.PbEq([(flag, 1) for flag in text_type_flags], 1),
                z3.Bool("detector_exec_text_1_is_str"),
                len_text == z3.Length(text),
                z3.PrefixOf(z3.StringVal("ab"), text),
                z3.SubString(text, 0, 1) == z3.StringVal("a"),
                z3.SubString(text, 1, 1) == z3.StringVal("b"),
                len_text == 2,
                salt == 2,
            ],
        )

        assert result is True
        assert executor.session.degraded_passes == []
        assert unknown_solver.prefix_args == [None]

    def test_detector_feasibility_accepts_string_ord_witness(self) -> None:
        """A validated string/ord assignment avoids solver UNKNOWN."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        text = z3.String("detector_exec_license_key_str")
        text_type_flags = [
            z3.Bool("detector_exec_license_key_is_int"),
            z3.Bool("detector_exec_license_key_is_bool"),
            z3.Bool("detector_exec_license_key_is_str"),
            z3.Bool("detector_exec_license_key_is_path"),
            z3.Bool("detector_exec_license_key_is_obj"),
            z3.Bool("detector_exec_license_key_is_none"),
            z3.Bool("detector_exec_license_key_is_float"),
            z3.Bool("detector_exec_license_key_is_list"),
            z3.Bool("detector_exec_license_key_is_dict"),
        ]
        len_text = z3.Int("len_exec_license_key_int")
        ord_values = [z3.Int(f"ord_19_8554{index}_int") for index in range(1, 10, 2)]
        witness_text = "\x00\x04\x04\x04\x88"

        result = _detector_query_is_sat(
            executor,
            [
                z3.PbEq([(flag, 1) for flag in text_type_flags], 1),
                z3.Bool("detector_exec_license_key_is_str"),
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
                (ord_values[0] * 65536 + ord_values[2] * 256 + ord_values[4]) % 16777216
                == 0x000488,
                ord_values[1] == ord_values[3],
                ord_values[1] - ord_values[3] == 0,
            ],
        )

        assert result is True
        assert executor.session.degraded_passes == []
        assert unknown_solver.prefix_args == [None]

    def test_detector_feasibility_tries_witness_before_rechecking_inconclusive_prefix(
        self,
    ) -> None:
        """A verified hard-theory witness may avoid repeating an inconclusive prefix query."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        text = z3.String("detector_inconclusive_text")
        prefix = (z3.Length(text) == 1,)

        result = detector_query_is_sat(
            session=executor.session,
            solver=executor.solver,
            constraints=[*prefix, text == z3.StringVal("a")],
            inconclusive_path_prefix=prefix,
        )

        assert result is True
        assert executor.session.degraded_passes == []
        assert unknown_solver.prefix_args == []

    def test_detector_feasibility_records_unknown_when_inconclusive_prefix_witness_fails(
        self,
    ) -> None:
        """Witness failure on an inconclusive prefix is explicitly degraded, not SAT."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        text = z3.String("detector_inconclusive_no_witness_text")
        prefix = (z3.Length(text) == 1,)

        result = detector_query_is_sat(
            session=executor.session,
            solver=executor.solver,
            constraints=[*prefix, text == z3.StringVal("a"), text != z3.StringVal("a")],
            inconclusive_path_prefix=prefix,
        )

        assert result is False
        assert executor.session.degraded_passes == [SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS]
        assert unknown_solver.prefix_args == []

    def test_detector_float_witness_must_satisfy_complete_query(self) -> None:
        """Zero assignment cannot report an infeasible guarded detector path."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        value = z3.FP("detector_guarded_float_x", z3.Float64())

        result = _detector_query_is_sat(
            executor,
            [z3.fpIsZero(value), z3.Not(z3.fpIsZero(value))],
        )

        assert result is False
