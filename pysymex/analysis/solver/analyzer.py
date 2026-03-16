"""
Z3 Engine — Function analyzer core.

The FunctionAnalyzer class performs symbolic execution on individual functions,
building crash conditions and function summaries. It inherits bytecode opcode
handlers from OpcodeHandlersMixin.
"""

from __future__ import annotations

import hashlib
import inspect
import logging
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from pysymex.analysis.solver.graph import CFGBuilder, SymbolicState
from pysymex.analysis.solver.opcodes import OpcodeHandlersMixin
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

if TYPE_CHECKING:
    from pysymex.analysis.solver import Z3Engine

logger = logging.getLogger(__name__)


class FunctionAnalyzer(OpcodeHandlersMixin):
    """Analyses individual functions via symbolic execution over the Z3 engine.

    Builds crash conditions and function summaries by exploring CFG paths.

    Attributes:
        engine: The parent ``Z3Engine`` instance.
        cfg_builder: Utility for building control-flow graphs.
        current_function: Name of the function being analysed.
        current_line: Current source line number.
        current_file: Path of the file being analysed.
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
    COMPARE_OPS: dict[str, Callable[[object, object], object]] = {
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
        code: object,
        initial_state: SymbolicState | None = None,
        context: dict[str, SymValue] | None = None,
    ) -> tuple[list[CrashCondition], FunctionSummary]:
        """Analyse a function and return crash conditions and a summary.

        Args:
            code: Python code object to analyse.
            initial_state: Optional pre-seeded symbolic state.
            context: Optional mapping of param names to ``SymValue`` overrides.

        Returns:
            Tuple of (crash conditions found, function summary).
        """
        param_annotations: dict[str, object] = {}
        if hasattr(code, "__code__"):
            func_obj = code
            code = code.__code__
            try:
                sig = inspect.signature(func_obj)
                for param_name, param in sig.parameters.items():
                    if param.annotation is not inspect.Signature.empty:
                        param_annotations[param_name] = param.annotation
                    elif param.default is not inspect.Signature.empty and param.default is not None:
                        param_annotations[param_name] = type(param.default)
            except (TypeError, ValueError):
                logger.debug("Failed to inspect function signature", exc_info=True)

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
                state.set_var(p, self._make_symbolic_param(p, param_annotations.get(p)))
        crashes: list[CrashCondition] = []
        call_sites: list[CallSite] = []
        self._explore_paths(cfg, 0, state, crashes, call_sites, visited=set(), depth=0)
        summary = self._build_summary(code, params, crashes, call_sites)
        return crashes, summary

    def _make_symbolic_param(self, name: str, annotation: object | None = None) -> SymValue:
        """Create a symbolic value for a parameter."""
        sym_type = self._annotation_to_sym_type(annotation)
        expr_name = name
        is_none = False
        is_list = False

        if sym_type == SymType.BOOL:
            expr = z3.Bool(expr_name)
        elif sym_type == SymType.REAL:
            expr = z3.Real(expr_name)
        elif sym_type == SymType.STRING:
            expr = z3.Int(f"{expr_name }_len")
        elif sym_type == SymType.LIST:
            expr = z3.Int(f"{expr_name }_len")
            is_list = True
        elif sym_type in {
            SymType.DICT,
            SymType.TUPLE,
            SymType.SET,
            SymType.CALLABLE,
            SymType.OBJECT,
        }:
            expr = z3.Int(f"{expr_name }_ref")
        elif sym_type == SymType.NONE:
            expr = z3.IntVal(0)
            is_none = True
        else:
            expr = z3.Int(expr_name)

        return SymValue(
            expr=expr,
            name=name,
            sym_type=sym_type,
            is_none=is_none,
            is_list=is_list,
            origin=f"param:{name }",
        )

    def _annotation_to_sym_type(self, annotation: object | None) -> SymType:
        """Annotation to sym type."""
        if annotation in (None, inspect.Signature.empty):
            return SymType.UNKNOWN
        if annotation is bool:
            return SymType.BOOL
        if annotation is int:
            return SymType.INT
        if annotation is float:
            return SymType.REAL
        if annotation is str:
            return SymType.STRING
        if annotation is list:
            return SymType.LIST
        if annotation is dict:
            return SymType.DICT
        if annotation is tuple:
            return SymType.TUPLE
        if annotation is set:
            return SymType.SET
        if annotation is type(None):
            return SymType.NONE
        annotation_str = str(annotation).lower()
        if "bool" in annotation_str:
            return SymType.BOOL
        if "float" in annotation_str:
            return SymType.REAL
        if "str" in annotation_str:
            return SymType.STRING
        if "list" in annotation_str:
            return SymType.LIST
        if "dict" in annotation_str:
            return SymType.DICT
        if "tuple" in annotation_str:
            return SymType.TUPLE
        if "set" in annotation_str:
            return SymType.SET
        if "callable" in annotation_str:
            return SymType.CALLABLE
        if "int" in annotation_str:
            return SymType.INT
        return SymType.UNKNOWN

    def _expr_fingerprint(self, expr: object) -> str:
        """Expr fingerprint."""
        if hasattr(expr, "sexpr"):
            try:
                return expr.sexpr()
            except z3.Z3Exception:
                logger.debug("Failed to serialize Z3 expression", exc_info=True)
        return repr(expr)

    def _symvalue_fingerprint(self, value: SymValue) -> str:
        """Symvalue fingerprint."""
        pieces = [
            value.name,
            value.sym_type.name,
            self._expr_fingerprint(value.expr),
            str(value.is_none),
            str(value.is_list),
        ]
        if value.length is not None:
            pieces.append(self._expr_fingerprint(value.length))
        pieces.extend(self._expr_fingerprint(c) for c in value.constraints)
        return "|".join(pieces)

    def _make_visit_key(self, block_id: int, state: SymbolicState) -> tuple[int, str]:
        """Make visit key."""
        hasher = hashlib.sha256()
        for constraint in state.path_constraints:
            hasher.update(self._expr_fingerprint(constraint).encode())
            hasher.update(b"\x00")
        for name, value in sorted(state.variables.items()):
            hasher.update(name.encode())
            hasher.update(b"\x01")
            hasher.update(self._symvalue_fingerprint(value).encode())
            hasher.update(b"\x00")
        for value in state.stack:
            hasher.update(self._symvalue_fingerprint(value).encode())
            hasher.update(b"\x02")
        return block_id, hasher.hexdigest()

    def _explore_paths(
        self,
        cfg: dict[int, BasicBlock],
        block_id: int,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
        visited: set[tuple[int, str]],
        depth: int,
    ) -> None:
        """Recursively explore CFG paths with duplicate-state pruning.

        Args:
            cfg: Mapping of block ID to ``BasicBlock``.
            block_id: Current block to explore.
            state: Current symbolic state.
            crashes: Accumulator for detected crash conditions.
            call_sites: Accumulator for discovered call sites.
            visited: Set of already-visited ``(block_id, constraint_key)`` tuples.
            depth: Current exploration depth.
        """
        if depth > self.engine.max_depth or block_id not in cfg:
            return
        visit_key = self._make_visit_key(block_id, state)
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

    def _update_line(self, instr: object) -> None:
        """Update current line number from instruction."""
        if hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
            self.current_line = instr.positions.lineno
        elif instr.starts_line and isinstance(instr.starts_line, int):
            self.current_line = instr.starts_line

    def _get_branch_constraint(self, opname: str, edge_type: str, cond: SymValue) -> object | None:
        """Get constraint for branch edge."""
        try:

            cond_expr = getattr(cond, "expr", None)
            if cond_expr is None:
                return None
            if edge_type == "fall":
                if opname == "POP_JUMP_IF_FALSE":
                    return cond_expr if z3.is_bool(cond_expr) else cond_expr != 0
                elif opname == "POP_JUMP_IF_TRUE":
                    return z3.Not(cond_expr) if z3.is_bool(cond_expr) else cond_expr == 0
                elif opname == "POP_JUMP_IF_NONE":
                    return cond_expr != 0
                elif opname == "POP_JUMP_IF_NOT_NONE":
                    return cond_expr == 0
            elif edge_type == "jump":
                if opname == "POP_JUMP_IF_FALSE":
                    return z3.Not(cond_expr) if z3.is_bool(cond_expr) else cond_expr == 0
                elif opname == "POP_JUMP_IF_TRUE":
                    return cond_expr if z3.is_bool(cond_expr) else cond_expr != 0
                elif opname == "POP_JUMP_IF_NONE":
                    return cond_expr == 0
                elif opname == "POP_JUMP_IF_NOT_NONE":
                    return cond_expr != 0
        except z3.Z3Exception:
            logger.debug("Failed to build edge condition for %s", opname, exc_info=True)
        return None

    def _is_path_feasible(self, constraints: list[object]) -> bool:
        """Quick check if path is feasible using IncrementalSolver."""
        if not constraints:
            return True
        from pysymex.core.solver import IncrementalSolver

        solver = IncrementalSolver(timeout_ms=200)
        return solver.is_sat(constraints)

    def _execute_instruction(
        self,
        instr: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        call_sites: list[CallSite],
    ) -> SymValue | None:
        """Execute single instruction symbolically."""
        op = instr.opname
        arg = instr.argval
        handler = getattr(self, f"_op_{op }", None)
        if handler:
            return handler(arg, state, crashes, call_sites)
        else:
            return self._op_unknown(op, arg, state, crashes, call_sites)

    def _do_binary_op(
        self, left: SymValue, right: SymValue, op: str, state: SymbolicState
    ) -> SymValue:
        """Perform binary operation with taint propagation."""
        taint = TaintInfo()

        left_is_tainted = getattr(left, "is_tainted", False)
        right_is_tainted = getattr(right, "is_tainted", False)
        left_taint = getattr(left, "taint", None)
        right_taint = getattr(right, "taint", None)
        if left_is_tainted or right_is_tainted:
            left_sources = getattr(left_taint, "sources", set()) if left_taint else set()
            right_sources = getattr(right_taint, "sources", set()) if right_taint else set()
            left_path = getattr(left_taint, "propagation_path", []) if left_taint else []
            taint = TaintInfo(
                is_tainted=True,
                sources=left_sources | right_sources,
                propagation_path=left_path + [op],
            )
        try:

            left_expr = getattr(left, "expr", None)
            right_expr = getattr(right, "expr", None)
            if left_expr is None or right_expr is None:
                expr = z3.Int(state.fresh_name("binop"))
            elif op == "+":
                expr = left_expr + right_expr
            elif op == "-":
                expr = left_expr - right_expr
            elif op == "*":
                expr = left_expr * right_expr
            elif op == "/":
                expr = z3.ToReal(left_expr) / z3.ToReal(right_expr)
            elif op == "//":
                expr = left_expr / right_expr
            elif op == "%":
                expr = left_expr % right_expr
            elif op == "&":
                expr = left_expr & right_expr
            elif op == "|":
                expr = left_expr | right_expr
            elif op == "^":
                expr = left_expr ^ right_expr
            elif op == "<<":
                expr = left_expr * (2**right_expr)
            elif op == ">>":
                expr = left_expr / (2**right_expr)
            elif op == "**":
                expr = z3.Int(state.fresh_name("pow"))
            else:
                expr = z3.Int(state.fresh_name("binop"))
            left_name = getattr(left, "name", "?")
            right_name = getattr(right, "name", "?")
            return SymValue(expr, f"({left_name}{op}{right_name})", SymType.INT, taint=taint)
        except z3.Z3Exception:
            logger.debug("Z3 binary op %s failed", op, exc_info=True)
            return SymValue(z3.Int(state.fresh_name("binop")), "", SymType.INT, taint=taint)

    def _check_division(
        self, divisor: SymValue, op: str, state: SymbolicState, crashes: list[CrashCondition]
    ):
        """Check for division by zero."""

        divisor_expr = getattr(divisor, "expr", None)
        divisor_name = getattr(divisor, "name", None)
        if divisor_expr is None:
            return
        name_str = divisor_name if divisor_name else "divisor"
        self._add_crash(
            BugType.DIVISION_BY_ZERO,
            divisor_expr == 0,
            state,
            crashes,
            f"Division by zero: {name_str} can be 0 in {op}",
            {name_str: divisor_expr},
            Severity.CRITICAL,
        )

    def _check_modulo(self, divisor: SymValue, state: SymbolicState, crashes: list[CrashCondition]):
        """Check for modulo by zero."""

        divisor_expr = getattr(divisor, "expr", None)
        divisor_name = getattr(divisor, "name", None)
        if divisor_expr is None:
            return
        name_str = divisor_name if divisor_name else "divisor"
        self._add_crash(
            BugType.MODULO_BY_ZERO,
            divisor_expr == 0,
            state,
            crashes,
            f"Modulo by zero: {name_str} can be 0",
            {name_str: divisor_expr},
            Severity.CRITICAL,
        )

    def _check_shift(
        self, amount: SymValue, op: str, state: SymbolicState, crashes: list[CrashCondition]
    ):
        """Check for negative shift amount."""

        amount_expr = getattr(amount, "expr", None)
        amount_name = getattr(amount, "name", None)
        if amount_expr is None:
            return
        name_str = amount_name if amount_name else "amount"
        self._add_crash(
            BugType.NEGATIVE_SHIFT,
            amount_expr < 0,
            state,
            crashes,
            f"Negative shift: {name_str} can be negative in {op}",
            {name_str: amount_expr},
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

        container_length = getattr(container, "length", None)
        index_expr = getattr(index, "expr", None)
        index_name = getattr(index, "name", None)
        if container_length is None or index_expr is None:
            return
        condition = z3.Or(index_expr < 0, index_expr >= container_length)
        name_str = index_name if index_name else "index"
        self._add_crash(
            BugType.INDEX_OUT_OF_BOUNDS,
            condition,
            state,
            crashes,
            f"Index out of bounds: {name_str}",
            {name_str: index_expr, "length": container_length},
            Severity.CRITICAL,
        )

    def _add_crash(
        self,
        bug_type: BugType,
        condition: object,
        state: SymbolicState,
        crashes: list[CrashCondition],
        description: str,
        variables: dict[str, object],
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

    def _make_const(self, value: object, state: SymbolicState) -> SymValue:
        """Create symbolic constant."""
        match value:
            case bool() as v:
                return SymValue(z3.BoolVal(v), str(v), SymType.BOOL)
            case int() as v:
                return SymValue(z3.IntVal(v), str(v), SymType.INT)
            case float() as v:
                return SymValue(z3.RealVal(v), str(v), SymType.REAL)
            case None:
                return SymValue(z3.IntVal(0), "None", SymType.NONE, is_none=True)
            case str() as v:
                return SymValue(z3.IntVal(len(v)), repr(v)[:20], SymType.STRING)
            case _:
                return SymValue(z3.Int(state.fresh_name("const")), "", SymType.UNKNOWN)

    def _empty_summary(self, code: object) -> FunctionSummary:
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
        code: object,
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
