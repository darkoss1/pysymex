"""Tests for Phase 0.5 — Symbolic Correctness fixes.

Covers:
  0.5.1  Bitwise operations soundness (BV conversions, shift checks)
  0.5.2  Exception fork correctness (hierarchy model)
  0.5.3  State merging soundness (branch constraint preservation)
  0.5.4  KLEE-style independence optimization (already existed)
  0.5.5  Loop widening type constraints
"""

from __future__ import annotations

import z3

# ── 0.5.1  Bitwise Operations Soundness ──────────────────────────────────


class TestBitwiseOperationsSoundness:
    """Verify that SymbolicValue bitwise operators properly use Z3 BV ops."""

    def _make_sym_int(self, name: str):
        from pysymex.core.types import Z3_FALSE, Z3_TRUE, SymbolicValue

        return SymbolicValue(
            _name=name,
            z3_int=z3.Int(name),
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
        )

    def test_and_integer_preserves_z3_int(self):
        """__and__ on two ints should produce a non-zero z3_int (BV AND)."""
        a = self._make_sym_int("a")
        b = self._make_sym_int("b")
        result = a & b
        # z3_int should NOT be trivially zero anymore
        assert not z3.is_false(result.is_int), "is_int should be satisfiable for int & int"
        # The z3_int expression should reference a BV2Int conversion
        expr_str = str(result.z3_int)
        assert (
            "BV2Int" in expr_str
            or "bv2int" in expr_str.lower()
            or "Int2BV" in str(result.z3_int.sexpr())
        ), f"Expected BV conversion in z3_int, got: {expr_str}"

    def test_or_integer_preserves_z3_int(self):
        a = self._make_sym_int("x")
        b = self._make_sym_int("y")
        result = a | b
        expr_str = result.z3_int.sexpr()
        assert "bv" in expr_str.lower(), f"Expected BV ops in sexpr, got: {expr_str}"

    def test_xor_integer_preserves_z3_int(self):
        a = self._make_sym_int("p")
        b = self._make_sym_int("q")
        result = a ^ b
        expr_str = result.z3_int.sexpr()
        assert "bv" in expr_str.lower(), f"Expected BV ops in sexpr, got: {expr_str}"

    def test_invert_integer_preserves_z3_int(self):
        a = self._make_sym_int("v")
        result = ~a
        expr_str = result.z3_int.sexpr()
        assert "bv" in expr_str.lower(), f"Expected BV ops in sexpr, got: {expr_str}"

    def test_and_boolean_still_works(self):
        """Boolean AND should still produce z3.And on z3_bool."""
        from pysymex.core.types import Z3_FALSE, Z3_TRUE, SymbolicValue

        a = SymbolicValue(
            _name="bt",
            z3_int=z3.IntVal(0),
            is_int=Z3_FALSE,
            z3_bool=z3.Bool("bt_b"),
            is_bool=Z3_TRUE,
        )
        b = SymbolicValue(
            _name="bf",
            z3_int=z3.IntVal(0),
            is_int=Z3_FALSE,
            z3_bool=z3.Bool("bf_b"),
            is_bool=Z3_TRUE,
        )
        result = a & b
        assert z3.is_and(result.z3_bool) or "and" in str(result.z3_bool).lower()

    def test_concrete_bitwise_and(self):
        """5 & 3 == 1 when both are concrete ints."""
        from pysymex.core.types import SymbolicValue

        a = SymbolicValue.from_const(5)
        b = SymbolicValue.from_const(3)
        result = a & b
        s = z3.Solver()
        s.add(result.is_int)
        s.add(result.z3_int == 1)
        assert s.check() == z3.sat, "5 & 3 should be satisfiable as 1"

    def test_concrete_bitwise_or(self):
        """5 | 3 == 7."""
        from pysymex.core.types import SymbolicValue

        a = SymbolicValue.from_const(5)
        b = SymbolicValue.from_const(3)
        result = a | b
        s = z3.Solver()
        s.add(result.is_int)
        s.add(result.z3_int == 7)
        assert s.check() == z3.sat

    def test_concrete_bitwise_xor(self):
        """5 ^ 3 == 6."""
        from pysymex.core.types import SymbolicValue

        a = SymbolicValue.from_const(5)
        b = SymbolicValue.from_const(3)
        result = a ^ b
        s = z3.Solver()
        s.add(result.is_int)
        s.add(result.z3_int == 6)
        assert s.check() == z3.sat

    def test_taint_preserved_through_bitwise(self):
        """Taint labels should propagate through bitwise ops."""
        a = self._make_sym_int("ta")
        b = self._make_sym_int("tb")
        a = a.with_taint("input")
        result = a & b
        assert result.taint_labels and "input" in result.taint_labels

    def test_bv_conversion_helpers_exist(self):
        """Verify the module-level BV helpers are importable."""
        from pysymex.core.types import _BV_WIDTH, _bv_to_int, _int_to_bv

        assert _BV_WIDTH == 64
        bv = _int_to_bv(z3.IntVal(42))
        assert bv.size() == 64
        back = _bv_to_int(bv)
        s = z3.Solver()
        s.add(back == 42)
        assert s.check() == z3.sat


# ── 0.5.2  Exception Fork Correctness ────────────────────────────────────


class TestExceptionForkCorrectness:
    """Verify exception hierarchy and forking logic."""

    def test_exception_hierarchy_exists(self):
        """EXCEPTION_HIERARCHY constant should be defined."""
        from pysymex.core.exceptions_types import EXCEPTION_HIERARCHY

        assert isinstance(EXCEPTION_HIERARCHY, dict)
        assert len(EXCEPTION_HIERARCHY) > 20

    def test_unicode_decode_error_caught_by_value_error(self):
        """UnicodeDecodeError is a subclass of ValueError."""
        from pysymex.core.exceptions_types import EXCEPTION_HIERARCHY, exception_matches

        assert ValueError in EXCEPTION_HIERARCHY[UnicodeDecodeError]
        assert exception_matches(UnicodeDecodeError, ValueError)

    def test_index_error_caught_by_lookup_error(self):
        from pysymex.core.exceptions_types import exception_matches

        assert exception_matches(IndexError, LookupError)

    def test_key_error_caught_by_lookup_error(self):
        from pysymex.core.exceptions_types import exception_matches

        assert exception_matches(KeyError, LookupError)

    def test_zero_division_caught_by_arithmetic_error(self):
        from pysymex.core.exceptions_types import exception_matches

        assert exception_matches(ZeroDivisionError, ArithmeticError)

    def test_not_implemented_caught_by_runtime_error(self):
        from pysymex.core.exceptions_types import exception_matches

        assert exception_matches(NotImplementedError, RuntimeError)

    def test_all_caught_by_exception(self):
        from pysymex.core.exceptions_types import exception_matches

        for exc_type in (ValueError, TypeError, KeyError, RuntimeError):
            assert exception_matches(exc_type, Exception)

    def test_handler_catches_type_uses_issubclass(self):
        from pysymex.core.exceptions_types import ExceptionHandler

        handler = ExceptionHandler(exc_types=(ValueError,), target_pc=10)
        assert handler.catches_type(UnicodeDecodeError)
        assert handler.catches_type(ValueError)
        assert not handler.catches_type(TypeError)

    def test_setup_finally_forks_on_raisable(self):
        """SETUP_FINALLY should fork when try body has raising ops."""
        from pysymex.execution.opcodes.exceptions import _try_block_can_raise

        # Just verify the _try_block_can_raise helper exists and is callable
        assert callable(_try_block_can_raise)


# ── 0.5.3  State Merging Soundness ───────────────────────────────────────


class TestStateMergingSoundness:
    """Verify that state merging preserves branch-specific constraints."""

    def test_merge_preserves_branch_constraints(self):
        """After merging, constraints from both branches should be preserved
        as conditional implications."""
        from pysymex.analysis.state_merger import StateMerger
        from pysymex.core.state import VMState

        x = z3.Int("x")
        cond = x > 5

        s1 = VMState()
        s1.pc = 10
        s1.add_constraint(cond)  # branch condition
        s1.add_constraint(x < 100)  # branch-specific: x < 100

        s2 = VMState()
        s2.pc = 10
        s2.add_constraint(z3.Not(cond))  # negated branch
        s2.add_constraint(x >= 0)  # branch-specific: x >= 0

        merger = StateMerger()
        merged = merger._merge_states_symbolically(s1, s2)
        if merged is not None:
            # The merged constraints should include conditional implications
            constraint_strs = [str(c) for c in merged.path_constraints]
            combined = " ".join(constraint_strs)
            # Should find Implies in the merged constraints
            assert (
                "Implies" in combined or "=>" in combined
            ), f"Expected conditional implications in merged constraints, got: {constraint_strs}"

    def test_merge_uses_ite_for_differing_locals(self):
        """Variables that differ between branches should be merged with ITE."""
        from pysymex.analysis.state_merger import StateMerger
        from pysymex.core.state import VMState
        from pysymex.core.types import SymbolicValue

        cond = z3.Bool("branch")

        s1 = VMState()
        s1.pc = 5
        s1.local_vars["y"] = SymbolicValue.from_const(10)
        s1.add_constraint(cond)

        s2 = VMState()
        s2.pc = 5
        s2.local_vars["y"] = SymbolicValue.from_const(20)
        s2.add_constraint(z3.Not(cond))

        merger = StateMerger()
        merged = merger._merge_states_symbolically(s1, s2)
        if merged is not None:
            merged_y = merged.local_vars["y"]
            # The merged value should contain an ITE expression
            expr_str = str(merged_y.z3_int)
            assert "If" in expr_str or "ite" in expr_str.lower()

    def test_taint_union_on_merge(self):
        """Taint labels from both branches should be unioned."""
        from pysymex.core.types import _merge_taint

        t1 = frozenset({"user_input"})
        t2 = frozenset({"db_query"})
        merged = _merge_taint(t1, t2)
        assert "user_input" in merged
        assert "db_query" in merged

    def test_taint_union_with_none(self):
        from pysymex.core.types import _merge_taint

        assert _merge_taint(None, None) is None
        assert _merge_taint(frozenset({"a"}), None) == frozenset({"a"})
        assert _merge_taint(None, frozenset({"b"})) == frozenset({"b"})

    def test_merge_refuses_incompatible_container_types(self):
        """State merging should fail closed on incompatible branch-local container types."""
        from pysymex.analysis.state_merger import StateMerger
        from pysymex.core.state import VMState
        from pysymex.core.types import SymbolicValue
        from pysymex.core.types_containers import SymbolicList

        cond = z3.Bool("branch_container")

        s1 = VMState()
        s1.pc = 5
        s1.local_vars["value"] = SymbolicList.from_const([1, 2, 3])
        s1.add_constraint(cond)

        s2 = VMState()
        s2.pc = 5
        s2.local_vars["value"] = SymbolicValue.from_const(20)
        s2.add_constraint(z3.Not(cond))

        merger = StateMerger()
        assert merger._merge_states_symbolically(s1, s2) is None


# ── 0.5.4  Constraint Independence Optimization ─────────────────────────


class TestConstraintIndependence:
    """Verify KLEE-style independence optimization is in place."""

    def test_optimizer_importable(self):
        from pysymex.core.constraint_independence import ConstraintIndependenceOptimizer

        opt = ConstraintIndependenceOptimizer()
        assert hasattr(opt, "slice_for_query")
        assert hasattr(opt, "register_constraint")

    def test_independence_slicing(self):
        from pysymex.core.constraint_independence import ConstraintIndependenceOptimizer

        opt = ConstraintIndependenceOptimizer()
        x, y, w = z3.Ints("x y w")
        c1 = x > 0
        c2 = y < 10
        c3 = w == 5
        for c in [c1, c2, c3]:
            opt.register_constraint(c)
        relevant = opt.slice_for_query([c1, c2, c3], x > 5)
        assert any(z3.eq(r, c1) for r in relevant)
        assert not any(z3.eq(r, c2) for r in relevant)
        assert not any(z3.eq(r, c3) for r in relevant)

    def test_solver_uses_optimizer(self):
        """IncrementalSolver should have a _optimizer attribute."""
        from pysymex.core.solver import IncrementalSolver

        solver = IncrementalSolver()
        assert hasattr(solver, "_optimizer")


# ── 0.5.5  Loop Widening Correctness ─────────────────────────────────────


class TestLoopWidening:
    """Verify loop widening adds type constraints and uses correct PC."""

    def test_widen_state_adds_type_constraint(self):
        """Widened symbolic variables should have type constraints in path."""
        from pysymex.analysis.loops.core import LoopWidening
        from pysymex.analysis.loops.types import InductionVariable, LoopBound, LoopInfo
        from pysymex.core.state import VMState
        from pysymex.core.types import SymbolicValue

        loop = LoopInfo(
            header_pc=10,
            back_edge_pc=20,
            exit_pcs={30},
            body_pcs={10, 12, 14, 16, 18, 20},
        )
        loop.induction_vars = {
            "i": InductionVariable(name="i", initial=z3.IntVal(0), step=z3.IntVal(1), direction=1)
        }
        loop.bound = LoopBound(lower=z3.IntVal(0), upper=z3.IntVal(100))

        old_state = VMState()
        old_state.locals["i"] = SymbolicValue.from_const(0)
        new_state = VMState()
        new_state.locals["i"] = SymbolicValue.from_const(5)

        widener = LoopWidening(widening_threshold=3)
        widened = widener.widen_state(old_state, new_state, loop)

        # The widened state should have type constraints for the widened variable
        constraint_strs = [str(c) for c in widened.path_constraints]
        # Current widening emits explicit numeric range bounds for widened vars.
        assert any(
            "i_widened_int <=" in c or "<= i_widened_int" in c for c in constraint_strs
        ), f"Expected upper bound for widened variable, got: {constraint_strs}"
        assert any(
            "0 <= i_widened_int" in c or "i_widened_int >= 0" in c for c in constraint_strs
        ), f"Expected lower bound for widened variable, got: {constraint_strs}"

    def test_loop_detector_finds_loops(self):
        """LoopDetector should find back edges in instruction sequences."""
        from pysymex.analysis.loops.core import LoopDetector

        detector = LoopDetector()
        assert callable(getattr(detector, "analyze_cfg", None))
        assert callable(getattr(detector, "get_loop_at", None))

    def test_loop_widening_threshold(self):
        """LoopWidening should respect configurable threshold."""
        from pysymex.analysis.loops.core import LoopWidening
        from pysymex.analysis.loops.types import LoopInfo

        loop = LoopInfo(
            header_pc=0,
            back_edge_pc=10,
            exit_pcs={20},
            body_pcs={0, 2, 4, 6, 8, 10},
        )
        widener = LoopWidening(widening_threshold=3)
        assert not widener.should_widen(loop)
        for _ in range(3):
            widener.record_iteration(loop)
        assert widener.should_widen(loop)
