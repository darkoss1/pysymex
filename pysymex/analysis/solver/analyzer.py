"""
Z3 Engine — Function analyzer core.

The FunctionAnalyzer class performs symbolic execution on individual functions,
building crash conditions and function summaries. It inherits bytecode opcode
handlers from OpcodeHandlersMixin.
"""

from __future__ import annotations


import hashlib

import logging

import time

from collections.abc import Callable

from typing import TYPE_CHECKING, Any


from pysymex.analysis.solver.types import (
    BasicBlock,
    BugType,
    CallSite,
    CrashCondition,
    FunctionSummary,
    Severity,
    SymType,
    SymValue,
    TaintInfo,
    z3,
)

from pysymex.analysis.solver.graph import CFGBuilder, SymbolicState

from pysymex.analysis.solver.opcodes import OpcodeHandlersMixin

if TYPE_CHECKING:
    from pysymex.analysis.solver import Z3Engine

logger = logging.getLogger(__name__)


class FunctionAnalyzer(OpcodeHandlersMixin):
    """
    Analyzes individual functions and creates summaries.
    """

    BINARY_OPS = {
        0: "+",
        1: "&",
        2: "//",
        3: "<<",
        4: "@",
        5: "*",
        6: "%",
        7: "|",
        8: "**",
        9: ">>",
        10: "-",
        11: "/",
        12: "^",
        13: "+=",
        14: "&=",
        15: "//=",
        16: "<<=",
        17: "@=",
        18: "*=",
        19: "%=",
        20: "|=",
        21: "**=",
        22: ">>=",
        23: "-=",
        24: "/=",
        25: "^=",
    }

    COMPARE_OPS: dict[str, Callable[[Any, Any], Any]] = {
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
    }

    DANGEROUS_SINKS = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "os.system",
        "subprocess.call",
        "subprocess.run",
        "open",
        "sqlite3.execute",
        "cursor.execute",
    }

    def __init__(self, engine: Z3Engine):
        self.engine = engine

        self.cfg_builder = CFGBuilder()

        self.current_function = ""

        self.current_line = 0

        self.current_file = ""

    def analyze(
        self,
        code: Any,
        initial_state: SymbolicState | None = None,
        context: dict[str, SymValue] | None = None,
    ) -> tuple[list[CrashCondition], FunctionSummary]:
        """
        Analyze a function and return crash conditions + summary.
        """

        self.current_function = code.co_name

        self.current_line = code.co_firstlineno

        cfg = self.cfg_builder.build(code)

        if not cfg:
            return [], self._empty_summary(code)

        state = initial_state or SymbolicState()

        state.call_stack.append(self.current_function)

        params = code.co_varnames[: code.co_argcount]

        for p in params:
            if context and p in context:
                state.set_var(p, context[p])

            else:
                state.set_var(p, self._make_symbolic_param(p))

        crashes: list[CrashCondition] = []

        call_sites: list[CallSite] = []

        self._explore_paths(cfg, 0, state, crashes, call_sites, visited=set(), depth=0)

        summary = self._build_summary(code, params, crashes, call_sites)

        return crashes, summary

    def _make_symbolic_param(self, name: str) -> SymValue:
        """Create symbolic value for a parameter."""

        return SymValue(expr=z3.Int(name), name=name, sym_type=SymType.INT, origin=f"param:{name}")

    def _explore_paths(
        self,
        cfg: dict[int, BasicBlock],
        block_id: int,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
        visited: set[tuple[int, frozenset[int]]],
        depth: int,
    ) -> None:
        """Explore paths with intelligent prioritization."""

        if depth > self.engine.max_depth or block_id not in cfg:
            return

        constraint_key: frozenset[int] = frozenset(id(c) for c in state.path_constraints[-5:])

        visit_key: tuple[int, frozenset[int]] = (block_id, constraint_key)

        if visit_key in visited and depth > 10:
            return

        visited = visited | {visit_key}

        block = cfg[block_id]

        if not block.reachable:
            return

        state = state.fork()

        last_cond: SymValue | None = None

        for instr in block.instructions:
            self._update_line(instr)

            last_cond = self._execute_instruction(instr, state, crashes, call_sites)

        for succ_id, edge_type in block.successors:
            new_state = state.fork()

            if last_cond is not None and block.instructions:
                constraint = self._get_branch_constraint(
                    block.instructions[-1].opname, edge_type, last_cond
                )

                if constraint is not None:
                    new_state.add_constraint(constraint)

            if self._is_path_feasible(new_state.path_constraints):
                priority_depth = depth + (2 if cfg[succ_id].loop_header else 1)

                self._explore_paths(
                    cfg, succ_id, new_state, crashes, call_sites, visited, priority_depth
                )

    def _update_line(self, instr: Any) -> None:
        """Update current line number from instruction."""

        if hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
            self.current_line = instr.positions.lineno

        elif instr.starts_line and isinstance(instr.starts_line, int):
            self.current_line = instr.starts_line

    def _get_branch_constraint(self, opname: str, edge_type: str, cond: SymValue) -> Any | None:
        """Get constraint for branch edge."""

        try:
            if edge_type == "fall":
                if opname == "POP_JUMP_IF_FALSE":
                    return cond.expr if z3.is_bool(cond.expr) else cond.expr != 0

                elif opname == "POP_JUMP_IF_TRUE":
                    return z3.Not(cond.expr) if z3.is_bool(cond.expr) else cond.expr == 0

                elif opname == "POP_JUMP_IF_NONE":
                    return cond.expr != 0

                elif opname == "POP_JUMP_IF_NOT_NONE":
                    return cond.expr == 0

            elif edge_type == "jump":
                if opname == "POP_JUMP_IF_FALSE":
                    return z3.Not(cond.expr) if z3.is_bool(cond.expr) else cond.expr == 0

                elif opname == "POP_JUMP_IF_TRUE":
                    return cond.expr if z3.is_bool(cond.expr) else cond.expr != 0

                elif opname == "POP_JUMP_IF_NONE":
                    return cond.expr == 0

                elif opname == "POP_JUMP_IF_NOT_NONE":
                    return cond.expr != 0

        except Exception:
            logger.debug("Failed to build edge condition for %s", opname, exc_info=True)

        return None

    def _is_path_feasible(self, constraints: list[Any]) -> bool:
        """Quick check if path is feasible using IncrementalSolver."""

        if not constraints:
            return True

        from pysymex.core.solver import IncrementalSolver

        solver = IncrementalSolver(timeout_ms=200)

        return solver.is_sat(constraints)

    def _execute_instruction(
        self,
        instr: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        """Execute single instruction symbolically."""

        op = instr.opname

        arg = instr.argval

        handler = getattr(self, f"_op_{op}", None)

        if handler:
            return handler(arg, state, crashes, call_sites)

        else:
            return self._op_unknown(op, arg, state, crashes, call_sites)

    def _do_binary_op(
        self, left: SymValue, right: SymValue, op: str, state: SymbolicState
    ) -> SymValue:
        """Perform binary operation with taint propagation."""

        taint = TaintInfo()

        if left.is_tainted or right.is_tainted:
            taint = TaintInfo(
                is_tainted=True,
                sources=left.taint.sources | right.taint.sources,
                propagation_path=left.taint.propagation_path + [op],
            )

        try:
            if op == "+":
                expr = left.expr + right.expr

            elif op == "-":
                expr = left.expr - right.expr

            elif op == "*":
                expr = left.expr * right.expr

            elif op == "/":
                expr = z3.ToReal(left.expr) / z3.ToReal(right.expr)

            elif op == "//":
                expr = left.expr / right.expr

            elif op == "%":
                expr = left.expr % right.expr

            elif op == "&":
                expr = left.expr & right.expr

            elif op == "|":
                expr = left.expr | right.expr

            elif op == "^":
                expr = left.expr ^ right.expr

            elif op == "<<":
                expr = left.expr * (2**right.expr)

            elif op == ">>":
                expr = left.expr / (2**right.expr)

            elif op == "**":
                expr = z3.Int(state.fresh_name("pow"))

            else:
                expr = z3.Int(state.fresh_name("binop"))

            return SymValue(expr, f"({left.name}{op}{right.name})", SymType.INT, taint=taint)

        except Exception:
            logger.debug("Z3 binary op %s failed", op, exc_info=True)

            return SymValue(z3.Int(state.fresh_name("binop")), "", SymType.INT, taint=taint)

    def _check_division(
        self, divisor: SymValue, op: str, state: SymbolicState, crashes: list[CrashCondition]
    ):
        """Check for division by zero."""

        self._add_crash(
            BugType.DIVISION_BY_ZERO,
            divisor.expr == 0,
            state,
            crashes,
            f"Division by zero: {divisor.name or 'divisor'} can be 0 in {op}",
            {divisor.name or "divisor": divisor.expr},
            Severity.CRITICAL,
        )

    def _check_modulo(self, divisor: SymValue, state: SymbolicState, crashes: list[CrashCondition]):
        """Check for modulo by zero."""

        self._add_crash(
            BugType.MODULO_BY_ZERO,
            divisor.expr == 0,
            state,
            crashes,
            f"Modulo by zero: {divisor.name or 'divisor'} can be 0",
            {divisor.name or "divisor": divisor.expr},
            Severity.CRITICAL,
        )

    def _check_shift(
        self, amount: SymValue, op: str, state: SymbolicState, crashes: list[CrashCondition]
    ):
        """Check for negative shift amount."""

        self._add_crash(
            BugType.NEGATIVE_SHIFT,
            amount.expr < 0,
            state,
            crashes,
            f"Negative shift: {amount.name or 'amount'} can be negative in {op}",
            {amount.name or "amount": amount.expr},
            Severity.CRITICAL,
        )

    def _check_index_bounds(
        self,
        index: SymValue,
        container: SymValue,
        state: SymbolicState,
        crashes: list[CrashCondition],
    ):
        """Check for index out of bounds."""

        if container.length is None:
            return

        condition = z3.Or(index.expr < 0, index.expr >= container.length)

        self._add_crash(
            BugType.INDEX_OUT_OF_BOUNDS,
            condition,
            state,
            crashes,
            f"Index out of bounds: {index.name or 'index'}",
            {index.name or "index": index.expr, "length": container.length},
            Severity.CRITICAL,
        )

    def _add_crash(
        self,
        bug_type: BugType,
        condition: Any,
        state: SymbolicState,
        crashes: list[CrashCondition],
        description: str,
        variables: dict[str, Any],
        severity: Severity = Severity.HIGH,
        taint_info: TaintInfo | None = None,
    ):
        """Add a crash condition."""

        crashes.append(
            CrashCondition(
                bug_type=bug_type,
                condition=condition,
                path_constraints=state.path_constraints.copy(),
                line=self.current_line,
                function=self.current_function,
                description=description,
                variables=variables,
                severity=severity,
                call_stack=state.call_stack.copy(),
                taint_info=taint_info,
                file_path=self.current_file,
            )
        )

    def _make_const(self, value: Any, state: SymbolicState) -> SymValue:
        """Create symbolic constant."""

        if isinstance(value, bool):
            return SymValue(z3.BoolVal(value), str(value), SymType.BOOL)

        elif isinstance(value, int):
            return SymValue(z3.IntVal(value), str(value), SymType.INT)

        elif isinstance(value, float):
            return SymValue(z3.RealVal(value), str(value), SymType.REAL)

        elif value is None:
            return SymValue(z3.IntVal(0), "None", SymType.NONE, is_none=True)

        elif isinstance(value, str):
            return SymValue(z3.IntVal(len(value)), repr(value)[:20], SymType.STRING)

        return SymValue(z3.Int(state.fresh_name("const")), "", SymType.UNKNOWN)

    def _empty_summary(self, code: Any) -> FunctionSummary:
        """Create empty summary for functions that can't be analyzed."""

        return FunctionSummary(
            name=code.co_name,
            code_hash="",
            parameters=list(code.co_varnames[: code.co_argcount]),
            return_constraints=[],
            crash_conditions=[],
            modifies_globals=set(),
            calls_functions=set(),
            may_return_none=True,
            may_raise=True,
            taint_propagation={},
            pure=False,
            analyzed_at=time.time(),
            verified=True,
            has_bugs=False,
        )

    def _build_summary(
        self,
        code: Any,
        params: tuple[str, ...],
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> FunctionSummary:
        """Build function summary from analysis results."""

        return FunctionSummary(
            name=code.co_name,
            code_hash=hashlib.sha256(code.co_code).hexdigest()[:32],
            parameters=list(params),
            return_constraints=[],
            crash_conditions=crashes,
            modifies_globals=set(),
            calls_functions={cs.callee for cs in call_sites},
            may_return_none=False,
            may_raise=len(crashes) > 0,
            taint_propagation={},
            pure=len(call_sites) == 0,
            analyzed_at=time.time(),
            verified=True,
            has_bugs=len(crashes) > 0,
        )
