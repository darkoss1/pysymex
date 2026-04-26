from __future__ import annotations

import z3

from pysymex.accel.chtd import BagSolution, ChtdBagSolver
from pysymex.accel.dispatcher import reset as reset_dispatcher
from pysymex.accel.dispatcher import get_dispatcher
from pysymex.accel.bytecode import compile_constraint
from pysymex.core.graph.treewidth import BranchInfo


def test_bag_solution_indices_use_little_endian_bit_order() -> None:
    # LSB-first: tautology over one variable yields low two bits set.
    reset_dispatcher()
    dispatcher = get_dispatcher()
    tautology = compile_constraint(z3.BoolVal(True), ["x"])
    bitmap = dispatcher.evaluate_bag(tautology).bitmap
    solution = BagSolution(bag_id=1, variables=["x", "y", "z"], bitmap=bitmap, count=2)
    indices = solution.get_satisfying_indices()
    assert list(indices) == [0, 1]


def test_solve_bag_returns_nonzero_count_for_satisfiable_bag() -> None:
    solver = ChtdBagSolver(use_sat=False, warmup=False)
    x = z3.Bool("x")
    bag = frozenset({1})
    branch_info = {
        1: BranchInfo(pc=1, raw_vars=frozenset({"x"}), base_vars=frozenset({"x"}), condition=x)
    }

    result = solver.solve_bag(bag, branch_info)
    assert result.is_satisfiable() is True
    assert result.count > 0


def test_wide_bag_over_12_vars_does_not_silently_become_unsat() -> None:
    solver = ChtdBagSolver(use_sat=False, warmup=False)
    vars_ = [z3.Bool(f"v{i}") for i in range(13)]
    cond = vars_[0]
    bag = frozenset({100})
    base_var_names = frozenset({f"v{i}" for i in range(13)})
    branch_info = {
        100: BranchInfo(pc=100, raw_vars=base_var_names, base_vars=base_var_names, condition=cond)
    }

    result = solver.solve_bag(bag, branch_info)
    assert len(result.variables) == 13
    assert result.count > 0


def test_dispatcher_routing_counter_increments_and_never_stalls() -> None:
    reset_dispatcher()
    dispatcher = get_dispatcher()
    x = z3.Bool("x")
    c = compile_constraint(x, ["x"])

    first = dispatcher.evaluate_bag(c)
    second = dispatcher.evaluate_bag(c)

    stats = dispatcher.get_routing_stats()
    routing = stats["routing_decisions"]
    assert isinstance(routing, dict)
    assert routing[first.backend_used.name] >= 1
    assert routing[second.backend_used.name] >= 1
