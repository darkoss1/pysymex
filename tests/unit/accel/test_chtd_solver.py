from __future__ import annotations

import z3

from pysymex.accel.chtd_solver import BagSolution, GPUBagSolver, create_gpu_bag_solver
from pysymex.accel.dispatcher import evaluate_bag
from pysymex.accel.bytecode import compile_constraint
from pysymex.core.graph.treewidth import BranchInfo, TreeDecomposition


class TestBagSolution:
    def test_is_satisfiable_num_states_and_indices(self) -> None:
        tautology = compile_constraint(z3.BoolVal(True), ["x", "y"])
        bitmap = evaluate_bag(tautology).bitmap
        sat = BagSolution(bag_id=1, variables=["x", "y"], bitmap=bitmap, count=4)
        unsat = BagSolution(bag_id=2, variables=["x"], bitmap=bitmap, count=0)

        assert sat.is_satisfiable() is True
        assert unsat.is_satisfiable() is False
        assert sat.num_states == 4
        assert list(sat.get_satisfying_indices()) == [0, 1, 2, 3]


class TestGPUBagSolver:
    def test_is_gpu_available_false_when_gpu_disabled(self) -> None:
        solver = GPUBagSolver(use_gpu=False, warmup=False)
        assert solver.is_gpu_available is False

    def test_solve_children_sequential(self) -> None:
        solver = GPUBagSolver(use_gpu=False, warmup=False)
        x = z3.Bool("x")
        y = z3.Bool("y")

        branch_info = {
            1: BranchInfo(pc=1, raw_vars=frozenset({"x"}), base_vars=frozenset({"x"}), condition=x),
            2: BranchInfo(pc=2, raw_vars=frozenset({"y"}), base_vars=frozenset({"y"}), condition=y),
        }
        children = [frozenset({1}), frozenset({2})]

        sols = solver.solve_children_sequential(children, branch_info)
        assert len(sols) == 2
        assert all(s.count > 0 for s in sols)

    def test_solve_bag_with_no_constraints_returns_all_sat_bitmap(self) -> None:
        solver = GPUBagSolver(use_gpu=False, warmup=False)
        result = solver.solve_bag(frozenset({1}), {})

        assert result.count == 2
        assert result.variables == ["_dummy"]
        assert result.is_satisfiable() is True

    def test_pass_message_and_get_messages_for_bag(self) -> None:
        solver = GPUBagSolver(use_gpu=False, warmup=False)
        tautology = compile_constraint(z3.BoolVal(True), ["x", "y"])
        bitmap = evaluate_bag(tautology).bitmap
        solution = BagSolution(bag_id=7, variables=["x", "y"], bitmap=bitmap, count=4)

        branch_info = {
            10: BranchInfo(
                pc=10,
                raw_vars=frozenset({"x"}),
                base_vars=frozenset({"x"}),
                condition=z3.Bool("x"),
            )
        }

        solver.pass_message(solution, parent_bag_id=99, adhesion=frozenset({10}), branch_info=branch_info)
        msgs = solver.get_messages_for_bag(99)

        assert len(msgs) == 1

    def test_clear_messages_preallocates_inboxes(self) -> None:
        solver = GPUBagSolver(use_gpu=False, warmup=False)
        solver.clear_messages(num_bags=3)

        assert len(solver.get_messages_for_bag(0)) == 0
        assert len(solver.get_messages_for_bag(1)) == 0
        assert len(solver.get_messages_for_bag(2)) == 0

    def test_propagate_all_sat_and_unsat_paths(self) -> None:
        solver = GPUBagSolver(use_gpu=False, warmup=False)
        x = z3.Bool("x")

        td = TreeDecomposition(
            bags={0: frozenset({1}), 1: frozenset({2})},
            tree_edges=[(1, 0)],
            adhesion={(1, 0): frozenset({1})},
            width=1,
            parent_map={1: 0},
        )

        sat_info = {
            1: BranchInfo(pc=1, raw_vars=frozenset({"x"}), base_vars=frozenset({"x"}), condition=x),
            2: BranchInfo(
                pc=2,
                raw_vars=frozenset({"x"}),
                base_vars=frozenset({"x"}),
                condition=z3.BoolVal(True),
            ),
        }
        unsat_info = {
            1: BranchInfo(pc=1, raw_vars=frozenset({"x"}), base_vars=frozenset({"x"}), condition=x),
            2: BranchInfo(
                pc=2,
                raw_vars=frozenset({"x"}),
                base_vars=frozenset({"x"}),
                condition=z3.BoolVal(False),
            ),
        }

        assert solver.propagate_all(td, sat_info) is True
        assert solver.propagate_all(td, unsat_info) is False


def test_create_gpu_bag_solver_factory() -> None:
    solver = create_gpu_bag_solver(use_gpu=False)
    assert isinstance(solver, GPUBagSolver)
    assert solver.is_gpu_available is False
