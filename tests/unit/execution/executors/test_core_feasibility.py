"""Tests for core symbolic executor feasibility behavior."""

from __future__ import annotations

import z3
import pytest

from pysymex.execution.detectors import SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS
from pysymex.execution.detectors.query import cache as query_cache
from pysymex.execution.detectors.query import storage as query_storage
from pysymex.execution.detectors.query.cache import (
    collect_detector_query_stats,
    detector_query_is_sat,
)
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.fallback import FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.config.settings import ExecutionConfig
from tests.unit.execution.executors.core_executor_helpers import (
    IncrementalSensitiveSolver,
    UnknownSolver,
)


def _detector_query_is_sat(executor: SymbolicExecutor, constraints: list[z3.BoolRef]) -> bool:
    return detector_query_is_sat(
        session=executor.session,
        solver=executor.solver,
        constraints=constraints,
    )


def _no_detector_witness_model(_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    return None


class TestSymbolicExecutorFeasibility:
    """Test suite for detector and path-feasibility behavior."""

    def test_detector_query_cache_reuses_exact_constraint_query(self) -> None:
        """Repeated detector queries with identical formulas should hit executor cache."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        x = z3.Int("detector_cache_x")

        assert _detector_query_is_sat(executor, [x > 0]) is True
        assert _detector_query_is_sat(executor, [x > 0]) is True

        stats = collect_detector_query_stats(executor.session)
        assert stats["cache_misses"] == 1
        assert stats["cache_hits"] == 1

    def test_detector_query_cache_drops_literal_true_constraints(self) -> None:
        """Literal truths should not prevent detector query cache reuse."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        x = z3.Int("detector_cache_true_x")

        assert _detector_query_is_sat(executor, [z3.BoolVal(True), x > 0]) is True
        assert _detector_query_is_sat(executor, [x > 0]) is True

        stats = collect_detector_query_stats(executor.session)
        assert stats["cache_misses"] == 1
        assert stats["cache_hits"] == 1

    def test_detector_query_cache_short_circuits_literal_false_without_solver(self) -> None:
        """Literal falsehoods are definitive UNSAT and should not call the solver."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        x = z3.Int("detector_cache_false_x")

        assert _detector_query_is_sat(executor, [x > 0, z3.BoolVal(False)]) is False

        stats = collect_detector_query_stats(executor.session)
        assert stats["cache_misses"] == 0
        assert stats["cache_hits"] == 0
        assert unknown_solver.prefix_args == []

    def test_detector_query_cache_strips_negated_literal_false_without_solver(self) -> None:
        """Syntactic ``Not(False)`` is a tautology and should not reach the solver."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver

        assert _detector_query_is_sat(executor, [z3.Not(z3.BoolVal(False))]) is True

        stats = collect_detector_query_stats(executor.session)
        assert stats["cache_misses"] == 0
        assert stats["cache_hits"] == 0
        assert unknown_solver.prefix_args == []

    def test_detector_query_cache_short_circuits_negated_literal_true_without_solver(self) -> None:
        """Syntactic ``Not(True)`` is definitive UNSAT and should not call the solver."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        x = z3.Int("detector_cache_not_true_x")

        assert _detector_query_is_sat(executor, [x > 0, z3.Not(z3.BoolVal(True))]) is False

        stats = collect_detector_query_stats(executor.session)
        assert stats["cache_misses"] == 0
        assert stats["cache_hits"] == 0
        assert unknown_solver.prefix_args == []

    def test_detector_query_cache_collision_falls_back_to_solver(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Hash collisions must not reuse SAT results for different formulas."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))

        def forced_cache_key(constraints: list[z3.BoolRef], hasher: object) -> int:
            _ = constraints
            _ = hasher
            return 1

        monkeypatch.setattr(query_storage, "structural_hash", forced_cache_key)
        x = z3.Int("detector_collision_x")
        y = z3.Int("detector_collision_y")

        assert _detector_query_is_sat(executor, [x > 0, x < 0]) is False
        assert _detector_query_is_sat(executor, [y > 0]) is True

        stats = collect_detector_query_stats(executor.session)
        assert stats["cache_misses"] == 2
        assert stats["cache_hits"] == 0

    def test_detector_feasibility_uses_full_constraints_not_prefix(self) -> None:
        """Detector bug reports require full-path feasibility, not suffix-only SAT."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        sensitive_solver = IncrementalSensitiveSolver()
        executor.solver = sensitive_solver
        x = z3.Int("detector_full_path_x")

        result = _detector_query_is_sat(executor, [x > 0, x < 0])

        assert result is False
        assert sensitive_solver.prefix_args == [None]

    def test_detector_feasibility_unknown_is_not_reportable_sat(self) -> None:
        """Detector feasibility must not turn solver UNKNOWN into definite SAT."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        x = z3.Bool("detector_unknown_x")

        result = _detector_query_is_sat(executor, [x])

        assert result is False
        assert executor.session.degraded_passes == [SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS]
        event = executor.session.fallback_events[-1]
        assert event.kind is FallbackKind.UNKNOWN
        assert event.label == SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS
        assert event.owner == "execution.detectors"
        assert event.reason == "solver returned unknown for detector query with 1 constraint(s)"
        assert event.soundness is SoundnessTag.INCONCLUSIVE
        assert event.false_positive_risk is RiskLevel.MEDIUM
        assert event.false_negative_risk is RiskLevel.MEDIUM
        assert unknown_solver.prefix_args == [None]

    def test_detector_feasibility_does_not_cache_solver_unknown_as_unsat(self) -> None:
        """An UNKNOWN detector query must not poison later definitive SAT checks."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        unknown_solver = UnknownSolver()
        executor.solver = unknown_solver
        x = z3.Bool("detector_unknown_cache_x")
        constraints = [x]

        assert _detector_query_is_sat(executor, constraints) is False

        definitive_solver = IncrementalSensitiveSolver()
        executor.solver = definitive_solver

        assert _detector_query_is_sat(executor, constraints) is True
        assert unknown_solver.prefix_args == [None]
        assert definitive_solver.prefix_args == [None]
        assert collect_detector_query_stats(executor.session)["cache_hits"] == 0
        assert executor.session.degraded_passes == [SOLVER_UNKNOWN_DETECTOR_QUERY_DEGRADED_PASS]
        assert len(executor.session.fallback_events) == 1

    def test_detector_feasibility_recovers_sat_from_model_retry_after_solver_unknown(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A model-backed retry may prove SAT after the cheaper detector query is UNKNOWN."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        solver = UnknownSolver()
        executor.solver = solver
        count = z3.Int("count_detector_model_retry_sat_int")

        monkeypatch.setattr(query_cache, "detector_witness_model", _no_detector_witness_model)
        monkeypatch.setattr(
            solver,
            "check_sat_cached",
            IncrementalSensitiveSolver().check_sat_cached,
        )

        result = _detector_query_is_sat(executor, [count == 4])

        assert result is True
        assert solver.prefix_args == [None]
        assert executor.session.degraded_passes == []
        assert collect_detector_query_stats(executor.session)["cache_misses"] == 1

    def test_detector_feasibility_recovers_unsat_from_model_retry_after_solver_unknown(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A model-backed retry may prove UNSAT without recording a degraded query."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        solver = UnknownSolver()
        executor.solver = solver
        count = z3.Int("count_detector_model_retry_unsat_int")

        monkeypatch.setattr(query_cache, "detector_witness_model", _no_detector_witness_model)
        monkeypatch.setattr(
            solver,
            "check_sat_cached",
            IncrementalSensitiveSolver().check_sat_cached,
        )

        result = _detector_query_is_sat(executor, [count == 1, count == 2])

        assert result is False
        assert solver.prefix_args == [None]
        assert executor.session.degraded_passes == []
        assert collect_detector_query_stats(executor.session)["cache_misses"] == 1

    def test_detector_feasibility_recovers_sat_from_detached_retry_after_active_unknown(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A detached retry may prove SAT when the active incremental context is unknown."""

        class ActiveUnknownSolver(UnknownSolver):
            def _effective_timeout_ms(self) -> int:
                return 5000

        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        solver = ActiveUnknownSolver()
        executor.solver = solver
        count = z3.Int("count_detector_detached_retry_sat_int")

        monkeypatch.setattr(query_cache, "detector_witness_model", _no_detector_witness_model)

        result = _detector_query_is_sat(executor, [count == 4])

        assert result is True
        assert solver.prefix_args == [None]
        assert executor.session.degraded_passes == []
        assert collect_detector_query_stats(executor.session)["cache_misses"] == 1

    def test_detector_feasibility_uses_solver_before_expensive_witness(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Definitive solver answers should not pay detector witness-search cost."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        x = z3.Int("detector_solver_first_x")
        y = z3.Int("detector_solver_first_y")

        def fail_witness_search(_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
            raise AssertionError("witness search should only run after solver UNKNOWN")

        monkeypatch.setattr(query_cache, "detector_witness_model", fail_witness_search)

        assert _detector_query_is_sat(executor, [x > 0]) is True
        assert _detector_query_is_sat(executor, [y > 0, y < 0]) is False

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
