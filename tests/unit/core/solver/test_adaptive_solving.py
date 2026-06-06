import z3
import pytest
from pysymex.execution.opcodes.common.control.feasibility import (
    is_complex_smt_theory,
    is_bitvector_smt_theory,
    constraints_include_bitvector_smt_theory,
    branch_feasible,
)


def test_is_complex_smt_theory_simple() -> None:
    """Scenario: Simple linear integer constraints are not classified as complex SMT theory."""
    x = z3.Int("x")
    y = z3.Int("y")
    assert is_complex_smt_theory(x > 0) is False
    assert is_complex_smt_theory(x + y == 10) is False
    # Constant multiplication is linear and simple
    assert is_complex_smt_theory(x * 5 == 20) is False


def test_is_complex_smt_theory_fpa() -> None:
    """Scenario: Floating-point constraints are correctly classified as complex SMT theory."""
    # Create Float32 variables/values
    fp_sort = z3.Float32()
    f = z3.FP("f", fp_sort)
    zero = z3.FPVal(0.0, fp_sort)
    assert is_complex_smt_theory(f > zero) is True


def test_is_complex_smt_theory_arrays() -> None:
    """Scenario: Array constraints are correctly classified as complex SMT theory."""
    a = z3.Array("a", z3.IntSort(), z3.IntSort())
    assert is_complex_smt_theory(z3.Select(a, z3.IntVal(0)) == 10) is True


def test_is_complex_smt_theory_bitvectors() -> None:
    """Scenario: Bit-vector guards are classified as complex SMT theory."""
    x = z3.Int("x")
    masked = z3.BV2Int(z3.Int2BV(x, 8) & z3.BitVecVal(3, 8), is_signed=False)

    assert is_complex_smt_theory(masked == 1) is True
    assert is_bitvector_smt_theory(masked == 1) is True
    assert constraints_include_bitvector_smt_theory([x > 0, masked == 1]) is True


def test_is_complex_smt_theory_nonlinear_div_mod() -> None:
    """Scenario: Division and modulo operations are classified as complex SMT theory."""
    x = z3.Int("x")
    y = z3.Int("y")
    assert is_complex_smt_theory(x / y == 2) is True
    assert is_complex_smt_theory(x % y == 1) is True


def test_is_complex_smt_theory_nonlinear_mul() -> None:
    """Scenario: Non-linear variable-variable multiplication is classified as complex SMT theory."""
    x = z3.Int("x")
    y = z3.Int("y")
    assert is_complex_smt_theory(x * y == 100) is True


def test_branch_feasible_simple_under_threshold() -> None:
    """Scenario: Simple linear constraint with count under 24; expected solved using SMT."""
    x = z3.Int("x")
    # Path constraint list of 10 items (under threshold 24)
    constraints = [x > i for i in range(10)]
    assert branch_feasible(constraints, x > 15) is True
    assert branch_feasible(constraints, x < -5) is False


def test_branch_feasible_does_not_trust_path_prefix_as_prechecked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Branch checks must include pending path constraints in the SMT query."""
    calls: list[tuple[list[z3.BoolRef], int | None]] = []

    def capture_path_query(
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        calls.append((constraints, known_sat_prefix_len))
        return True

    monkeypatch.setattr(
        "pysymex.core.solver.engine.policies.path_may_be_feasible",
        capture_path_query,
    )
    x = z3.Int("branch_full_prefix_x")
    prefix = [x > 0]
    extra = x < 10

    assert branch_feasible(prefix, extra) is True

    assert calls == [([*prefix, extra], None)]


def test_branch_feasible_forwards_known_sat_prefix_len(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Branch checks can mark only the proven prefix as already SAT."""
    calls: list[tuple[list[z3.BoolRef], int | None]] = []

    def capture_path_query(
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        calls.append((constraints, known_sat_prefix_len))
        return True

    monkeypatch.setattr(
        "pysymex.core.solver.engine.policies.path_may_be_feasible",
        capture_path_query,
    )
    x = z3.Int("branch_known_prefix_x")
    y = z3.Int("branch_known_prefix_y")
    prefix = [x > 0, y > 0]
    extra = x < 10

    assert branch_feasible(prefix, extra, known_sat_prefix_len=1) is True

    assert calls == [([*prefix, extra], 1)]


def test_branch_feasible_skips_solver_for_bitvector_path_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bit-vector-heavy prefixes are left feasible instead of spending SMT prune time."""

    def fail_path_query(
        _constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = known_sat_prefix_len
        raise AssertionError("bit-vector path prefixes should bypass branch SMT pruning")

    monkeypatch.setattr(
        "pysymex.core.solver.engine.policies.path_may_be_feasible",
        fail_path_query,
    )
    x = z3.Int("branch_bitvector_prefix_x")
    masked = z3.BV2Int(z3.Int2BV(x, 8) & z3.BitVecVal(3, 8), is_signed=False)

    assert branch_feasible([masked == 1], x > 0) is True


def test_branch_feasible_complex_under_threshold() -> None:
    """Scenario: Complex constraint with count under 8; expected solved using SMT."""
    # FPA variable
    fp_sort = z3.Float32()
    f = z3.FP("f", fp_sort)
    zero = z3.FPVal(0.0, fp_sort)
    constraints = [f > zero]
    assert branch_feasible(constraints, f < zero) is False


def test_branch_feasible_long_path_uses_solver_for_nontrivial_contradictions() -> None:
    """Scenario: Long simple path still uses SMT; expected infeasible branch is pruned."""
    x = z3.Int("x")
    constraints = [z3.Int(f"p{i}") == i for i in range(24)]

    assert branch_feasible(constraints, z3.And(x > 0, x < 0)) is False


def test_branch_feasible_long_path_keeps_satisfiable_branch() -> None:
    """Scenario: Long simple path with feasible branch remains feasible."""
    x = z3.Int("x")
    constraints = [z3.Int(f"q{i}") == i for i in range(24)]

    assert branch_feasible(constraints, z3.And(x > 0, x < 5)) is True
