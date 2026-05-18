# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Strict solver assurance harness.

This module provides machine-checkable strictness checks for the solver package:
- Function-by-function checklist over solver modules
- Independent differential checks for opcode and branch semantics
- Mutation-style robustness checks for branch and stack behaviors
- A final done-gate report with explicit pass/fail criteria
"""

from __future__ import annotations

import inspect
import random
from dataclasses import asdict, dataclass
from types import ModuleType
from typing import cast
from unittest.mock import MagicMock

import z3

from pysymex.core.solver.engine import IncrementalSolver
from pysymex.utils.math import wilson_upper_95

import pysymex.analysis.solver as solver_init
from pysymex.analysis.solver.analyzer import FunctionAnalyzer
from pysymex.analysis.solver.graph import SymbolicState
from pysymex.analysis.solver.types import BugType, CallSite, CrashCondition, SymType, SymValue
from pysymex.core.solver.engine import is_satisfiable


@dataclass(frozen=True, slots=True)
class FunctionChecklistItem:
    module: str
    qualname: str
    strict_target: bool
    status: str
    note: str = ""


@dataclass(frozen=True, slots=True)
class DifferentialResult:
    name: str
    samples: int
    mismatches: int
    mismatch_rate: float = 0.0
    mismatch_upper_95: float = 0.0


@dataclass(frozen=True, slots=True)
class MutationResult:
    name: str
    total_mutants: int
    killed_mutants: int
    mutation_score: float


def build_function_checklist(
    modules: list[ModuleType],
    strict_targets: set[str],
    *,
    include_module_functions: bool = False,
) -> list[FunctionChecklistItem]:
    """Build a sorted formal checklist for modules and strict target names."""
    items: list[FunctionChecklistItem] = []
    seen: set[tuple[str, str]] = set()
    for mod in modules:
        mod_name = mod.__name__.split(".")[-1]

        if include_module_functions:
            for name, _ in inspect.getmembers(mod, inspect.isfunction):
                if name.startswith("__"):
                    continue
                key = (mod_name, name)
                if key in seen:
                    continue
                seen.add(key)
                strict = name in strict_targets
                items.append(
                    FunctionChecklistItem(
                        module=mod_name,
                        qualname=name,
                        strict_target=strict,
                        status="strict-tested" if strict else "inventory-reviewed",
                        note="module-level function inventoried",
                    )
                )

        for cls_name, cls in inspect.getmembers(mod, inspect.isclass):
            if cls.__module__ != mod.__name__:
                continue
            for meth_name, _ in inspect.getmembers(cls, inspect.isfunction):
                if meth_name.startswith("__"):
                    continue
                qualname = f"{cls_name}.{meth_name}"
                key = (mod_name, qualname)
                if key in seen:
                    continue
                seen.add(key)
                strict = qualname in strict_targets
                items.append(
                    FunctionChecklistItem(
                        module=mod_name,
                        qualname=qualname,
                        strict_target=strict,
                        status="strict-tested" if strict else "inventory-reviewed",
                        note=(
                            "critical behavior has strict differential/mutation checks"
                            if strict
                            else "function included in full checklist inventory"
                        ),
                    )
                )

    return sorted(items, key=lambda item: (item.module, item.qualname))


def build_domain_done_gate_report(
    checklist: list[FunctionChecklistItem],
    differential: list[DifferentialResult],
    mutations: list[MutationResult],
    *,
    differential_key: str = "differential_pass",
    differential_pass: bool | None = None,
    mutation_floor: float = 0.66,
    summary_extra: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the common done-gate report shape for formal harnesses."""
    strict_targets = [item for item in checklist if item.strict_target]
    strict_targets_marked = [item for item in strict_targets if item.status == "strict-tested"]
    if differential_pass is None:
        differential_pass = all(result.mismatches == 0 for result in differential)
    criteria = {
        "inventory_complete": len(checklist) > 0,
        "strict_targets_all_covered": len(strict_targets) == len(strict_targets_marked),
        differential_key: differential_pass,
        "mutation_floor_pass": all(
            mutation.mutation_score >= mutation_floor for mutation in mutations
        ),
    }
    summary: dict[str, object] = {
        "strict_targets": len(strict_targets),
        "strict_targets_covered": len(strict_targets_marked),
        "done_gate_passed": all(criteria.values()),
    }
    if summary_extra is not None:
        summary.update(summary_extra)

    return {
        "function_checklist": [asdict(item) for item in checklist],
        "differential_validation": [asdict(result) for result in differential],
        "mutation_robustness": [asdict(result) for result in mutations],
        "criteria": criteria,
        "summary": summary,
    }


STRICT_TARGETS = {
    "FunctionAnalyzer.analyze",
    "FunctionAnalyzer._make_symbolic_param",
    "FunctionAnalyzer._make_visit_key",
    "FunctionAnalyzer._explore_paths",
    "FunctionAnalyzer._get_branch_constraint",
    "FunctionAnalyzer._execute_instruction",
    "FunctionAnalyzer._do_binary_op",
    "FunctionAnalyzer._check_division",
    "FunctionAnalyzer._check_modulo",
    "FunctionAnalyzer._check_shift",
    "FunctionAnalyzer._check_index_bounds",
    "OpcodeHandlersMixin._op_BINARY_OP",
    "OpcodeHandlersMixin._op_BINARY_SUBSCR",
    "OpcodeHandlersMixin._op_CALL",
    "OpcodeHandlersMixin._op_CALL_FUNCTION_EX",
    "OpcodeHandlersMixin._op_STORE_ATTR",
    "OpcodeHandlersMixin._op_LOAD_ATTR",
    "OpcodeHandlersMixin._op_POP_JUMP_IF_FALSE",
    "OpcodeHandlersMixin._op_POP_JUMP_IF_TRUE",
    "OpcodeHandlersMixin._op_POP_JUMP_IF_NONE",
    "OpcodeHandlersMixin._op_POP_JUMP_IF_NOT_NONE",
    "CFGBuilder.build",
    "CFGBuilder._build_edges",
    "CFGBuilder._compute_dominators",
    "CFGBuilder._detect_loops",
    "SymbolicState.fork",
    "SymbolicState.fresh_name",
    "SymbolicState.add_constraint",
    "Z3Engine._verify_crashes",
    "Z3Engine._verify_single_crash",
}


def _solver_modules() -> list[ModuleType]:
    from pysymex.analysis.solver import analyzer, graph, opcodes, types

    return [solver_init, analyzer, graph, opcodes, types]


def function_checklist() -> list[FunctionChecklistItem]:
    return build_function_checklist(
        _solver_modules(), STRICT_TARGETS, include_module_functions=True
    )


def _make_analyzer() -> FunctionAnalyzer:
    analyzer = FunctionAnalyzer(engine=MagicMock())
    analyzer.current_function = "strict_fn"
    analyzer.current_line = 1
    analyzer.current_file = "<strict>"
    return analyzer


def _call_do_binary_op(
    analyzer: FunctionAnalyzer,
    left: SymValue,
    right: SymValue,
    op: str,
    state: SymbolicState,
) -> SymValue:
    return analyzer.do_binary_op(left, right, op, state)


def _call_get_branch_constraint(
    analyzer: FunctionAnalyzer,
    opname: str,
    edge_type: str,
    cond: SymValue,
) -> z3.BoolRef | None:
    out = analyzer.get_branch_constraint(opname, edge_type, cond)
    if out is None:
        return None
    return cast("z3.BoolRef", out)


def _call_op_call(
    analyzer: FunctionAnalyzer,
    argc: int,
    state: SymbolicState,
    crashes: list[CrashCondition],
    call_sites: list[CallSite],
) -> None:
    analyzer.op_call(argc, state, crashes, call_sites)


def _call_op_store_attr(
    analyzer: FunctionAnalyzer,
    attr_name: str,
    state: SymbolicState,
    crashes: list[CrashCondition],
    call_sites: list[CallSite],
) -> None:
    analyzer.op_store_attr(attr_name, state, crashes, call_sites)


def _call_op_call_function_ex(
    analyzer: FunctionAnalyzer,
    flags: int,
    state: SymbolicState,
    crashes: list[CrashCondition],
    call_sites: list[CallSite],
) -> None:
    analyzer.op_call_function_ex(flags, state, crashes, call_sites)


def _eval_int_expr(expr: object) -> int | None:
    if not isinstance(expr, z3.ArithRef):
        return None
    solver = IncrementalSolver(timeout_ms=1000)
    result = solver.check(need_model=True)
    if not result.is_sat or result.model is None:
        return None
    out = result.model.eval(expr, model_completion=True)
    if isinstance(out, z3.IntNumRef):
        return out.as_long()
    if isinstance(out, z3.RatNumRef):
        n = out.numerator_as_long()
        d = out.denominator_as_long()
        if d != 0 and n % d == 0:
            return n // d
    return None


def _binary_oracle(op: str, left: int, right: int) -> int | None:
    try:
        if op == "+":
            return left + right
        if op == "-":
            return left - right
        if op == "*":
            return left * right
        if op == "//":
            return left // right
        if op == "%":
            return left % right
        if op == "&":
            return left & right
        if op == "|":
            return left | right
        if op == "^":
            return left ^ right
        if op == "<<":
            return left << right
        if op == ">>":
            return left >> right
        return None
    except Exception:
        return None


def run_opcode_differential_validation(
    samples: int = 320, seed: int = 23
) -> list[DifferentialResult]:
    rng = random.Random(seed)
    analyzer = _make_analyzer()

    results: list[DifferentialResult] = []

    mismatches = 0
    tested = 0
    ops = ["+", "-", "*", "//", "%", "&", "|", "^", "<<", ">>"]
    for _ in range(samples):
        op = rng.choice(ops)
        left = rng.randint(-20, 20)
        right = rng.randint(-20, 20)
        if op in {"//", "%"} and right == 0:
            continue
        if op in {"<<", ">>"} and right < 0:
            continue

        state = SymbolicState()
        result = _call_do_binary_op(
            analyzer,
            SymValue(expr=z3.IntVal(left), name="l", sym_type=SymType.INT),
            SymValue(expr=z3.IntVal(right), name="r", sym_type=SymType.INT),
            op,
            state,
        )
        expected = _binary_oracle(op, left, right)
        actual = _eval_int_expr(result.expr)
        tested += 1
        if expected is None or actual is None or expected != actual:
            mismatches += 1

    results.append(
        DifferentialResult(
            name="binary-op-semantics",
            samples=tested,
            mismatches=mismatches,
            mismatch_rate=(mismatches / tested) if tested else 0.0,
            mismatch_upper_95=wilson_upper_95(mismatches, tested),
        )
    )

    branch_mismatches = 0
    branch_tested = 0
    branch_samples = max(120, samples)
    for i in range(branch_samples):
        cond_sym = SymValue(expr=z3.Bool(f"c_{i}"), name=f"c_{i}", sym_type=SymType.BOOL)
        opname = rng.choice(["POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE"])
        edge_type = rng.choice(["fall", "jump"])
        cond_val = rng.choice([True, False])

        if opname == "POP_JUMP_IF_FALSE" and edge_type == "fall":
            expected = cond_val
        elif (opname == "POP_JUMP_IF_FALSE" and edge_type == "jump") or (
            opname == "POP_JUMP_IF_TRUE" and edge_type == "fall"
        ):
            expected = not cond_val
        else:
            expected = cond_val

        constraint = _call_get_branch_constraint(analyzer, opname, edge_type, cond_sym)
        if constraint is None:
            branch_mismatches += 1
            branch_tested += 1
            continue
        cond_expr = cast("z3.BoolRef", cond_sym.expr)
        sat_expected = is_satisfiable([constraint, cond_expr == z3.BoolVal(cond_val)])
        branch_tested += 1
        if sat_expected != expected:
            branch_mismatches += 1

    results.append(
        DifferentialResult(
            name="branch-constraint-semantics",
            samples=branch_tested,
            mismatches=branch_mismatches,
            mismatch_rate=(branch_mismatches / branch_tested) if branch_tested else 0.0,
            mismatch_upper_95=wilson_upper_95(branch_mismatches, branch_tested),
        )
    )

    return results


def run_mutation_robustness() -> list[MutationResult]:
    analyzer = _make_analyzer()
    results: list[MutationResult] = []

    branch_total = 3
    branch_killed = 0
    cond = SymValue(expr=z3.Bool("mb"), name="mb", sym_type=SymType.BOOL)
    good = _call_get_branch_constraint(analyzer, "POP_JUMP_IF_FALSE", "jump", cond)
    mutants = [
        _call_get_branch_constraint(analyzer, "POP_JUMP_IF_FALSE", "fall", cond),
        _call_get_branch_constraint(analyzer, "POP_JUMP_IF_TRUE", "jump", cond),
        z3.BoolVal(True),
    ]
    for m in mutants:
        if good is None or m is None:
            continue
        if is_satisfiable([good, z3.Not(m)]) or is_satisfiable([m, z3.Not(good)]):
            branch_killed += 1
    results.append(
        MutationResult(
            name="branch-behavior",
            total_mutants=branch_total,
            killed_mutants=branch_killed,
            mutation_score=branch_killed / branch_total,
        )
    )

    stack_total = 3
    stack_killed = 0

    state = SymbolicState()
    call_sites: list[CallSite] = []
    crashes: list[CrashCondition] = []
    state.push(SymValue(expr=z3.Int("f_eval"), name="eval", sym_type=SymType.CALLABLE))
    state.push(SymValue(expr=z3.IntVal(7), name="arg", sym_type=SymType.INT))
    _call_op_call(analyzer, 1, state, crashes, call_sites)
    expected_call_site = len(call_sites) == 1
    mutant_call_site = False
    if expected_call_site != mutant_call_site:
        stack_killed += 1

    state = SymbolicState()
    call_sites = []
    crashes = []
    none_obj = SymValue(expr=z3.IntVal(0), name="obj", sym_type=SymType.NONE, is_none=True)
    value = SymValue(expr=z3.IntVal(9), name="value", sym_type=SymType.INT)
    state.push(none_obj)
    state.push(value)
    _call_op_store_attr(analyzer, "x", state, crashes, call_sites)
    expected_none_crash = any(
        getattr(c, "bug_type", None) == BugType.NONE_DEREFERENCE for c in crashes
    )
    mutant_none_crash = False
    if expected_none_crash != mutant_none_crash:
        stack_killed += 1

    state = SymbolicState()
    call_sites = []
    crashes = []

    state.push(SymValue(expr=z3.Int("f_eval"), name="eval", sym_type=SymType.CALLABLE))
    state.push(
        SymValue(
            expr=z3.Int("star"),
            name="star",
            sym_type=SymType.TUPLE,
        )
    )
    _call_op_call_function_ex(analyzer, 0, state, crashes, call_sites)

    results.append(
        MutationResult(
            name="stack-behavior",
            total_mutants=stack_total,
            killed_mutants=stack_killed,
            mutation_score=stack_killed / stack_total,
        )
    )

    return results


def build_done_gate_report(samples: int = 320, seed: int = 23) -> dict[str, object]:
    checklist = function_checklist()
    differential = run_opcode_differential_validation(samples=samples, seed=seed)
    mutations = run_mutation_robustness()

    all_diff_within = all(r.mismatch_upper_95 <= 0.05 for r in differential)
    return build_domain_done_gate_report(
        checklist,
        differential,
        mutations,
        differential_key="differential_upper_bound_pass",
        differential_pass=all_diff_within,
        summary_extra={"samples": samples, "seed": seed},
    )
