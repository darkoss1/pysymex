import warnings

import z3

import pysymex.core.solver.engine as mod


class TestSolverResult:
    def test_sat(self) -> None:
        result = mod.SolverResult.sat(None)
        assert result.is_sat and not result.is_unsat

    def test_unsat(self) -> None:
        result = mod.SolverResult.unsat()
        assert result.is_unsat and not result.is_sat

    def test_unknown(self) -> None:
        result = mod.SolverResult.unknown()
        assert result.is_unknown


class TestIncrementalSolver:
    def test_reset(self) -> None:
        solver = mod.IncrementalSolver()
        solver.push()
        solver.reset()
        assert solver.get_stats()["scope_depth"] == 0

    def test_constraint_optimizer(self) -> None:
        solver = mod.IncrementalSolver()
        assert solver.constraint_optimizer() is not None

    def test_push(self) -> None:
        solver = mod.IncrementalSolver()
        solver.push()
        assert solver.get_stats()["scope_depth"] == 1

    def test_pop(self) -> None:
        solver = mod.IncrementalSolver()
        solver.push()
        solver.pop()
        assert solver.get_stats()["scope_depth"] == 0

    def test_add(self) -> None:
        solver = mod.IncrementalSolver()
        solver.add(z3.Bool("a"))
        assert solver.get_stats()["queries"] == 0

    def test_enter_scope(self) -> None:
        solver = mod.IncrementalSolver()
        solver.enter_scope([z3.Bool("a")])
        assert solver.get_stats()["scope_depth"] == 1

    def test_leave_scope(self) -> None:
        solver = mod.IncrementalSolver()
        solver.enter_scope([])
        solver.leave_scope()
        assert solver.get_stats()["scope_depth"] == 0

    def test_check(self) -> None:
        solver = mod.IncrementalSolver()
        result = solver.check()
        assert result.is_sat

    def test_is_sat(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        assert solver.is_sat([x > 0])

    def test_check_sat_cached(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        result = solver.check_sat_cached([x > 0])
        assert result.is_sat

    def test_get_model(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        model = solver.get_model([x == 2])
        assert model is not None

    def test_get_model_string(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        model_str = solver.get_model_string([x == 2])
        assert model_str is not None

    def test_extract_counterexample(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        data = solver.extract_counterexample([x == 3])
        assert isinstance(data, dict)

    def test_implies(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        assert solver.implies(x > 1, x > 0)

    def test_simplify(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        simplified = solver.simplify(x + 0)
        assert z3.is_expr(simplified)

    def test_get_unsat_core(self) -> None:
        solver = mod.IncrementalSolver()
        x = z3.Int("x")
        core = solver.get_unsat_core([x > 0, x < 0])
        assert core is not None

    def test_get_stats(self) -> None:
        solver = mod.IncrementalSolver()
        stats = solver.get_stats()
        assert "queries" in stats and "cache_hits" in stats


class TestPortfolioSolver:
    def test_check_hard(self) -> None:
        solver = mod.PortfolioSolver(timeout_ms=200, fast_timeout_ms=50, max_workers=1)
        result = solver.check_hard([z3.BoolVal(True)])
        assert isinstance(result, mod.SolverResult)


def test_create_solver() -> None:
    solver = mod.create_solver()
    assert isinstance(solver, z3.Solver)


def test_is_satisfiable() -> None:
    x = z3.Int("x")
    assert mod.is_satisfiable([x == 1])


def test_get_model() -> None:
    x = z3.Int("x")
    assert mod.get_model([x == 1]) is not None


def test_get_model_string() -> None:
    x = z3.Int("x")
    assert mod.get_model_string([x == 1]) is not None


def test_prove() -> None:
    x = z3.Int("x")
    assert mod.prove(x == x)


def test_clear_solver_caches() -> None:
    mod.clear_solver_caches()
    assert isinstance(mod.DEFAULT_SOLVER_TIMEOUT_MS, int)
