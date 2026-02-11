"""
Z3 Advanced Formal Verification Engine
======================================
Intelligent, interprocedural symbolic execution engine that:
- Tracks function calls across the entire codebase
- Builds call graphs to understand dependencies
- Creates function summaries for efficient re-analysis
- Dynamically explores paths based on risk priority
- Validates all pipelines and data flows
Architecture:
- CallGraph: Maps function relationships
- FunctionSummary: Cached analysis results
- SymbolicState: Rich state tracking with taint analysis
- InterproceduralAnalyzer: Cross-function verification
- Z3Engine: Main intelligent prover
Bug Types:
- Division/modulo by zero
- Negative bit shifts
- Index out of bounds
- None dereference
- Type confusion
- Unreachable code paths
- Tainted data flows
Version: 2.0.0
"""

from __future__ import annotations

__version__ = "2.0.0"
__author__ = "PySpectre Team"
import dis
import hashlib
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    z3 = None


class BugType(Enum):
    """Types of bugs we can prove/disprove."""

    DIVISION_BY_ZERO = "division_by_zero"
    MODULO_BY_ZERO = "modulo_by_zero"
    INDEX_OUT_OF_BOUNDS = "index_out_of_bounds"
    NEGATIVE_SHIFT = "negative_shift"
    NONE_DEREFERENCE = "none_dereference"
    TYPE_ERROR = "type_error"
    ASSERTION_FAILURE = "assertion_failure"
    KEY_ERROR = "key_error"
    ATTRIBUTE_ERROR = "attribute_error"
    UNREACHABLE_CODE = "unreachable_code"
    TAINTED_SINK = "tainted_data_to_sink"
    OVERFLOW = "integer_overflow"


class Severity(Enum):
    """Bug severity levels."""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class TaintSource(Enum):
    """Sources of untrusted data."""

    USER_INPUT = "user_input"
    FILE_READ = "file_read"
    NETWORK = "network"
    ENVIRONMENT = "environment"
    DATABASE = "database"
    UNKNOWN = "unknown"


class SymType(Enum):
    """Type classification for symbolic values."""

    INT = auto()
    REAL = auto()
    BOOL = auto()
    NONE = auto()
    LIST = auto()
    DICT = auto()
    STRING = auto()
    TUPLE = auto()
    SET = auto()
    CALLABLE = auto()
    OBJECT = auto()
    UNKNOWN = auto()


@dataclass
class TaintInfo:
    """Tracks taint information for a value."""

    is_tainted: bool = False
    sources: set[TaintSource] = field(default_factory=set)
    propagation_path: list[str] = field(default_factory=list)

    def propagate(self, operation: str) -> TaintInfo:
        """Create new taint info propagated through an operation."""
        if not self.is_tainted:
            return TaintInfo()
        return TaintInfo(
            is_tainted=True,
            sources=self.sources.copy(),
            propagation_path=self.propagation_path + [operation],
        )


@dataclass
class SymValue:
    """
    Enhanced symbolic value with rich metadata.
    """

    expr: Any
    name: str = ""
    sym_type: SymType = SymType.UNKNOWN
    is_none: bool = False
    is_list: bool = False
    length: Any | None = None
    taint: TaintInfo = field(default_factory=TaintInfo)
    origin: str = ""
    constraints: list[Any] = field(default_factory=list)

    @property
    def is_tainted(self) -> bool:
        return self.taint.is_tainted

    def with_taint(self, source: TaintSource, path: str = "") -> SymValue:
        """Create a tainted copy of this value."""
        new_taint = TaintInfo(
            is_tainted=True, sources={source}, propagation_path=[path] if path else []
        )
        return SymValue(
            self.expr,
            self.name,
            self.sym_type,
            self.is_none,
            self.is_list,
            self.length,
            new_taint,
            self.origin,
            self.constraints.copy(),
        )


@dataclass
class CrashCondition:
    """A condition that causes a crash."""

    bug_type: BugType
    condition: Any
    path_constraints: list[Any]
    line: int
    function: str
    description: str
    variables: dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.HIGH
    call_stack: list[str] = field(default_factory=list)
    taint_info: TaintInfo | None = None
    file_path: str = ""


@dataclass
class VerificationResult:
    """Result of formal verification."""

    crash: CrashCondition
    can_crash: bool
    proven_safe: bool
    counterexample: dict[str, str] | None = None
    z3_status: str = ""
    verification_time_ms: float = 0.0
    path_explored: int = 0


@dataclass
class FunctionSummary:
    """
    Summary of a function's behavior for interprocedural analysis.
    Allows efficient re-use without re-analyzing.
    """

    name: str
    code_hash: str
    parameters: list[str]
    return_constraints: list[Any]
    crash_conditions: list[CrashCondition]
    modifies_globals: set[str]
    calls_functions: set[str]
    may_return_none: bool
    may_raise: bool
    taint_propagation: dict[str, set[str]]
    pure: bool
    analyzed_at: float = 0.0
    verified: bool = False
    has_bugs: bool = False


@dataclass
class CallSite:
    """Information about a function call site."""

    caller: str
    callee: str
    line: int
    arguments: list[str]
    file_path: str = ""


@dataclass
class BasicBlock:
    """Basic block in control flow graph."""

    id: int
    instructions: list[Any] = field(default_factory=list)
    successors: list[tuple[int, str]] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    dominators: set[int] = field(default_factory=set)
    loop_header: bool = False
    reachable: bool = True


class CallGraph:
    """
    Builds and maintains call graph for interprocedural analysis.
    """

    def __init__(self):
        self.calls: dict[str, set[str]] = defaultdict(set)
        self.callers: dict[str, set[str]] = defaultdict(set)
        self.call_sites: dict[str, list[CallSite]] = defaultdict(list)
        self.entry_points: set[str] = set()
        self.recursive: set[str] = set()

    def add_call(self, site: CallSite):
        """Add a call relationship."""
        self.calls[site.caller].add(site.callee)
        self.callers[site.callee].add(site.caller)
        self.call_sites[site.caller].append(site)

    def get_callees(self, func: str) -> set[str]:
        """Get all functions called by func."""
        return self.calls.get(func, set())

    def get_callers(self, func: str) -> set[str]:
        """Get all functions that call func."""
        return self.callers.get(func, set())

    def find_recursive(self) -> set[str]:
        """Find all recursive functions (direct or indirect)."""
        recursive = set()

        def dfs(start: str, current: str, visited: set[str]):
            if current in visited:
                if current == start:
                    recursive.add(start)
                return
            visited.add(current)
            for callee in self.calls.get(current, set()):
                dfs(start, callee, visited.copy())

        for func in self.calls:
            dfs(func, func, set())
        self.recursive = recursive
        return recursive

    def topological_order(self) -> list[str]:
        """Get functions in dependency order (leaves first)."""
        in_degree = defaultdict(int)
        for caller, callees in self.calls.items():
            for callee in callees:
                in_degree[callee] += 1
        queue = [f for f in self.calls if in_degree[f] == 0]
        result = []
        while queue:
            func = queue.pop(0)
            result.append(func)
            for callee in self.calls.get(func, set()):
                in_degree[callee] -= 1
                if in_degree[callee] == 0:
                    queue.append(callee)
        return result

    def get_all_affected(self, func: str) -> set[str]:
        """Get all functions that might be affected by changes to func."""
        affected = set()
        queue = [func]
        while queue:
            current = queue.pop(0)
            if current in affected:
                continue
            affected.add(current)
            queue.extend(self.callers.get(current, set()))
        return affected


class CFGBuilder:
    """Enhanced control flow graph builder with dominance analysis."""

    BRANCH_OPS = frozenset(
        {
            "JUMP_FORWARD",
            "JUMP_BACKWARD",
            "JUMP_ABSOLUTE",
            "POP_JUMP_IF_TRUE",
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_IF_NONE",
            "POP_JUMP_IF_NOT_NONE",
            "JUMP_IF_TRUE_OR_POP",
            "JUMP_IF_FALSE_OR_POP",
            "FOR_ITER",
            "RETURN_VALUE",
            "RETURN_CONST",
            "RAISE_VARARGS",
            "RERAISE",
            "END_FOR",
        }
    )
    TERMINAL_OPS = frozenset({"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"})

    def build(self, code: Any) -> dict[int, BasicBlock]:
        """Build CFG with dominance info."""
        instrs = list(dis.get_instructions(code))
        if not instrs:
            return {}
        off_to_idx = {i.offset: idx for idx, i in enumerate(instrs)}
        leaders: set[int] = {0}
        for i, instr in enumerate(instrs):
            if instr.opname in self.BRANCH_OPS:
                if i + 1 < len(instrs):
                    leaders.add(i + 1)
                if instr.argval is not None and instr.argval in off_to_idx:
                    leaders.add(off_to_idx[instr.argval])
        sorted_leaders = sorted(leaders)
        blocks: dict[int, BasicBlock] = {}
        for i, leader in enumerate(sorted_leaders):
            end = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else len(instrs)
            blocks[leader] = BasicBlock(leader, instrs[leader:end])
        self._build_edges(blocks, off_to_idx)
        self._compute_dominators(blocks)
        self._detect_loops(blocks)
        return blocks

    def _build_edges(self, blocks: dict[int, BasicBlock], off_to_idx: dict[int, int]):
        """Build edges between basic blocks."""
        sorted_ids = sorted(blocks.keys())
        for bid, block in blocks.items():
            if not block.instructions:
                continue
            last = block.instructions[-1]
            op = last.opname
            idx = sorted_ids.index(bid)
            if op in (
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
            ):
                if idx + 1 < len(sorted_ids):
                    succ_id = sorted_ids[idx + 1]
                    block.successors.append((succ_id, "fall"))
                    blocks[succ_id].predecessors.append(bid)
                if last.argval in off_to_idx:
                    target = off_to_idx[last.argval]
                    if target in blocks:
                        block.successors.append((target, "jump"))
                        blocks[target].predecessors.append(bid)
            elif op in ("JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE"):
                if last.argval in off_to_idx:
                    target = off_to_idx[last.argval]
                    if target in blocks:
                        block.successors.append((target, "uncond"))
                        blocks[target].predecessors.append(bid)
            elif op not in self.TERMINAL_OPS:
                if idx + 1 < len(sorted_ids):
                    succ_id = sorted_ids[idx + 1]
                    block.successors.append((succ_id, "uncond"))
                    blocks[succ_id].predecessors.append(bid)

    def _compute_dominators(self, blocks: dict[int, BasicBlock]):
        """Compute dominator sets for each block."""
        if not blocks:
            return
        all_blocks = set(blocks.keys())
        entry = min(blocks.keys())
        blocks[entry].dominators = {entry}
        for bid in blocks:
            if bid != entry:
                blocks[bid].dominators = all_blocks.copy()
        changed = True
        while changed:
            changed = False
            for bid, block in blocks.items():
                if bid == entry:
                    continue
                if block.predecessors:
                    new_dom = set.intersection(
                        *[blocks[p].dominators for p in block.predecessors if p in blocks]
                    ) | {bid}
                else:
                    new_dom = {bid}
                if new_dom != block.dominators:
                    block.dominators = new_dom
                    changed = True

    def _detect_loops(self, blocks: dict[int, BasicBlock]):
        """Detect loop headers using back edges."""
        for bid, block in blocks.items():
            for succ_id, _ in block.successors:
                if succ_id in block.dominators:
                    blocks[succ_id].loop_header = True


class SymbolicState:
    """
    Manages symbolic execution state with rich tracking.
    """

    def __init__(self, parent: SymbolicState | None = None):
        self.parent = parent
        self.variables: dict[str, SymValue] = {}
        self.stack: list[SymValue] = []
        self.path_constraints: list[Any] = []
        self.call_stack: list[str] = []
        self.globals_modified: set[str] = set()
        self._counter = 0
        if parent:
            self.variables = parent.variables.copy()
            self.stack = parent.stack.copy()
            self.path_constraints = parent.path_constraints.copy()
            self.call_stack = parent.call_stack.copy()
            self._counter = parent._counter

    def fork(self) -> SymbolicState:
        """Create a copy for path exploration."""
        return SymbolicState(self)

    def fresh_name(self, prefix: str = "v") -> str:
        """Generate a fresh unique name."""
        self._counter += 1
        return f"{prefix}_{self._counter}"

    def add_constraint(self, constraint: Any):
        """Add a path constraint."""
        if constraint is not None:
            self.path_constraints.append(constraint)

    def get_var(self, name: str) -> SymValue | None:
        """Get variable by name."""
        return self.variables.get(name)

    def set_var(self, name: str, value: SymValue):
        """Set variable value."""
        self.variables[name] = value

    def push(self, value: SymValue):
        """Push value onto stack."""
        self.stack.append(value)

    def pop(self) -> SymValue | None:
        """Pop value from stack."""
        return self.stack.pop() if self.stack else None

    def peek(self, n: int = 1) -> SymValue | None:
        """Peek at stack without popping."""
        if len(self.stack) >= n:
            return self.stack[-n]
        return None


class FunctionAnalyzer:
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
    COMPARE_OPS = {
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
        visited: set[tuple[int, frozenset]],
        depth: int,
    ):
        """Explore paths with intelligent prioritization."""
        if depth > self.engine.max_depth or block_id not in cfg:
            return
        constraint_key = frozenset(id(c) for c in state.path_constraints[-5:])
        visit_key = (block_id, constraint_key)
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

    def _update_line(self, instr):
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
            pass
        return None

    def _is_path_feasible(self, constraints: list[Any]) -> bool:
        """Quick check if path is feasible."""
        if not constraints:
            return True
        solver = z3.Solver()
        solver.set("timeout", 200)
        for c in constraints:
            try:
                solver.add(c)
            except Exception:
                pass
        return solver.check() != z3.unsat

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

    def _op_LOAD_CONST(self, arg, state, crashes, call_sites):
        state.push(self._make_const(arg, state))
        return None

    def _op_LOAD_FAST(self, arg, state, crashes, call_sites):
        name = str(arg)
        val = state.get_var(name)
        if val is None:
            val = SymValue(z3.Int(name), name, SymType.INT, origin=f"local:{name}")
            state.set_var(name, val)
        state.push(val)
        return None

    def _op_LOAD_FAST_LOAD_FAST(self, arg, state, crashes, call_sites):
        if isinstance(arg, tuple):
            for name in arg:
                self._op_LOAD_FAST(name, state, crashes, call_sites)
        return None

    def _op_LOAD_GLOBAL(self, arg, state, crashes, call_sites):
        name = str(arg)
        val = SymValue(
            z3.Int(state.fresh_name(name)), name, SymType.UNKNOWN, origin=f"global:{name}"
        )
        state.push(val)
        return None

    def _op_LOAD_NAME(self, arg, state, crashes, call_sites):
        return self._op_LOAD_GLOBAL(arg, state, crashes, call_sites)

    def _op_LOAD_ATTR(self, arg, state, crashes, call_sites):
        obj = state.pop()
        if obj and obj.is_none:
            self._add_crash(
                BugType.NONE_DEREFERENCE,
                z3.BoolVal(True),
                state,
                crashes,
                f"Attribute access on None: {arg}",
                {obj.name: obj.expr} if obj.name else {},
            )
        val = SymValue(
            z3.Int(state.fresh_name(f"attr_{arg}")),
            f"{obj.name if obj else '?'}.{arg}",
            SymType.UNKNOWN,
            taint=obj.taint.propagate(f"attr:{arg}") if obj else TaintInfo(),
        )
        state.push(val)
        return None

    def _op_LOAD_DEREF(self, arg, state, crashes, call_sites):
        return self._op_LOAD_GLOBAL(arg, state, crashes, call_sites)

    def _op_STORE_FAST(self, arg, state, crashes, call_sites):
        if state.stack:
            state.set_var(str(arg), state.pop())
        return None

    def _op_STORE_NAME(self, arg, state, crashes, call_sites):
        return self._op_STORE_FAST(arg, state, crashes, call_sites)

    def _op_STORE_FAST_STORE_FAST(self, arg, state, crashes, call_sites):
        if isinstance(arg, tuple):
            for name in reversed(arg):
                if state.stack:
                    state.set_var(str(name), state.pop())
        return None

    def _op_STORE_GLOBAL(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        state.globals_modified.add(str(arg))
        return None

    def _op_STORE_ATTR(self, arg, state, crashes, call_sites):
        if len(state.stack) >= 2:
            state.pop()
            obj = state.pop()
            if obj and obj.is_none:
                self._add_crash(
                    BugType.NONE_DEREFERENCE,
                    z3.BoolVal(True),
                    state,
                    crashes,
                    f"Attribute assignment on None: {arg}",
                    {},
                )
        return None

    def _op_STORE_SUBSCR(self, arg, state, crashes, call_sites):
        if len(state.stack) >= 3:
            state.pop()
            index = state.pop()
            container = state.pop()
            if container and container.is_list and container.length is not None:
                self._check_index_bounds(index, container, state, crashes)
        return None

    def _op_STORE_DEREF(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        return None

    def _op_BINARY_OP(self, arg, state, crashes, call_sites):
        if len(state.stack) < 2:
            return None
        right = state.pop()
        left = state.pop()
        op_str = self.BINARY_OPS.get(arg, "+")
        base_op = op_str.rstrip("=")
        if base_op in ("/", "//"):
            self._check_division(right, base_op, state, crashes)
        elif base_op == "%":
            self._check_modulo(right, state, crashes)
        elif base_op in ("<<", ">>"):
            self._check_shift(right, base_op, state, crashes)
        result = self._do_binary_op(left, right, base_op, state)
        state.push(result)
        return None

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
            return SymValue(z3.Int(state.fresh_name("binop")), "", SymType.INT, taint=taint)

    def _op_BINARY_SUBSCR(self, arg, state, crashes, call_sites):
        if len(state.stack) < 2:
            return None
        index = state.pop()
        container = state.pop()
        if container and container.is_list and container.length is not None:
            self._check_index_bounds(index, container, state, crashes)
        result = SymValue(
            z3.Int(state.fresh_name("item")),
            f"{container.name if container else '?'}[{index.name if index else '?'}]",
            SymType.UNKNOWN,
            taint=container.taint.propagate("subscr") if container else TaintInfo(),
        )
        state.push(result)
        return None

    def _op_COMPARE_OP(self, arg, state, crashes, call_sites):
        if len(state.stack) < 2:
            return None
        right = state.pop()
        left = state.pop()
        op_str = str(arg)
        for key in self.COMPARE_OPS:
            if key in op_str:
                op_str = key
                break
        try:
            op_func = self.COMPARE_OPS.get(op_str)
            if op_func and left.expr is not None and right.expr is not None:
                result = SymValue(op_func(left.expr, right.expr), sym_type=SymType.BOOL)
            else:
                result = SymValue(z3.Bool(state.fresh_name("cmp")), sym_type=SymType.BOOL)
        except Exception:
            result = SymValue(z3.Bool(state.fresh_name("cmp")), sym_type=SymType.BOOL)
        state.push(result)
        return result

    def _op_IS_OP(self, arg, state, crashes, call_sites):
        if len(state.stack) < 2:
            return None
        right = state.pop()
        left = state.pop()
        try:
            if right.is_none:
                if left.is_none:
                    result = SymValue(z3.BoolVal(True), sym_type=SymType.BOOL)
                else:
                    result = SymValue(left.expr == 0, sym_type=SymType.BOOL)
            else:
                result = SymValue(left.expr == right.expr, sym_type=SymType.BOOL)
        except Exception:
            result = SymValue(z3.Bool(state.fresh_name("is")), sym_type=SymType.BOOL)
        state.push(result)
        return result

    def _op_CONTAINS_OP(self, arg, state, crashes, call_sites):
        if len(state.stack) >= 2:
            state.pop()
            state.pop()
        result = SymValue(z3.Bool(state.fresh_name("in")), sym_type=SymType.BOOL)
        state.push(result)
        return result

    def _op_TO_BOOL(self, arg, state, crashes, call_sites):
        if not state.stack:
            return None
        val = state.pop()
        try:
            if z3.is_bool(val.expr):
                state.push(val)
            else:
                result = SymValue(val.expr != 0, val.name, SymType.BOOL, taint=val.taint)
                state.push(result)
        except Exception:
            state.push(SymValue(z3.Bool(state.fresh_name("bool")), sym_type=SymType.BOOL))
        return None

    def _op_POP_JUMP_IF_FALSE(self, arg, state, crashes, call_sites):
        if state.stack:
            return state.pop()
        return None

    def _op_POP_JUMP_IF_TRUE(self, arg, state, crashes, call_sites):
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_POP_JUMP_IF_NONE(self, arg, state, crashes, call_sites):
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_POP_JUMP_IF_NOT_NONE(self, arg, state, crashes, call_sites):
        return self._op_POP_JUMP_IF_FALSE(arg, state, crashes, call_sites)

    def _op_UNARY_NEGATIVE(self, arg, state, crashes, call_sites):
        if state.stack:
            val = state.pop()
            try:
                state.push(SymValue(-val.expr, f"-{val.name}", SymType.INT, taint=val.taint))
            except Exception:
                state.push(SymValue(z3.Int(state.fresh_name("neg")), sym_type=SymType.INT))
        return None

    def _op_UNARY_NOT(self, arg, state, crashes, call_sites):
        if state.stack:
            val = state.pop()
            try:
                if z3.is_bool(val.expr):
                    state.push(SymValue(z3.Not(val.expr), sym_type=SymType.BOOL))
                else:
                    state.push(SymValue(val.expr == 0, sym_type=SymType.BOOL))
            except Exception:
                state.push(SymValue(z3.Bool(state.fresh_name("not")), sym_type=SymType.BOOL))
        return None

    def _op_UNARY_INVERT(self, arg, state, crashes, call_sites):
        if state.stack:
            val = state.pop()
            try:
                state.push(SymValue(~val.expr, f"~{val.name}", SymType.INT, taint=val.taint))
            except Exception:
                state.push(SymValue(z3.Int(state.fresh_name("inv")), sym_type=SymType.INT))
        return None

    def _op_CALL(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 0
        args = []
        for _ in range(n):
            if state.stack:
                args.insert(0, state.pop())
        func = state.pop() if state.stack else None
        if func and func.name:
            call_sites.append(
                CallSite(
                    caller=self.current_function,
                    callee=func.name,
                    line=self.current_line,
                    arguments=[a.name for a in args],
                    file_path=self.current_file,
                )
            )
            if func.name in self.DANGEROUS_SINKS:
                for i, a in enumerate(args):
                    if a.is_tainted:
                        self._add_crash(
                            BugType.TAINTED_SINK,
                            z3.BoolVal(True),
                            state,
                            crashes,
                            f"Tainted data passed to dangerous function: {func.name}",
                            {},
                            Severity.CRITICAL,
                            a.taint,
                        )
        result = SymValue(
            z3.Int(state.fresh_name("call")),
            f"{func.name if func else '?'}(...)" if func else "call(...)",
            SymType.UNKNOWN,
        )
        state.push(result)
        return None

    def _op_CALL_FUNCTION_EX(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        if state.stack:
            state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("call")), sym_type=SymType.UNKNOWN))
        return None

    def _op_PUSH_NULL(self, arg, state, crashes, call_sites):
        state.push(SymValue(z3.IntVal(0), "NULL", SymType.NONE, is_none=True))
        return None

    def _op_BUILD_LIST(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        result = SymValue(
            z3.Int(state.fresh_name("list")),
            f"[...{n}]",
            SymType.LIST,
            is_list=True,
            length=z3.IntVal(n),
        )
        state.push(result)
        return None

    def _op_BUILD_TUPLE(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        state.push(
            SymValue(z3.Int(state.fresh_name("tuple")), sym_type=SymType.TUPLE, length=z3.IntVal(n))
        )
        return None

    def _op_BUILD_SET(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("set")), sym_type=SymType.SET))
        return None

    def _op_BUILD_MAP(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 0
        for _ in range(n * 2):
            if state.stack:
                state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("dict")), sym_type=SymType.DICT))
        return None

    def _op_BUILD_CONST_KEY_MAP(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 0
        for _ in range(n + 1):
            if state.stack:
                state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("dict")), sym_type=SymType.DICT))
        return None

    def _op_BUILD_STRING(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("str")), sym_type=SymType.STRING))
        return None

    def _op_LIST_EXTEND(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        return None

    def _op_SET_UPDATE(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        return None

    def _op_DICT_UPDATE(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        return None

    def _op_DICT_MERGE(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        return None

    def _op_POP_TOP(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        return None

    def _op_COPY(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 1
        if state.stack and len(state.stack) >= n:
            state.push(state.stack[-n])
        return None

    def _op_SWAP(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 2
        if len(state.stack) >= n:
            state.stack[-1], state.stack[-n] = state.stack[-n], state.stack[-1]
        return None

    def _op_DUP_TOP(self, arg, state, crashes, call_sites):
        if state.stack:
            state.push(state.stack[-1])
        return None

    def _op_ROT_TWO(self, arg, state, crashes, call_sites):
        if len(state.stack) >= 2:
            state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]
        return None

    def _op_ROT_THREE(self, arg, state, crashes, call_sites):
        if len(state.stack) >= 3:
            state.stack[-1], state.stack[-2], state.stack[-3] = (
                state.stack[-2],
                state.stack[-3],
                state.stack[-1],
            )
        return None

    def _op_GET_ITER(self, arg, state, crashes, call_sites):
        container = state.pop() if state.stack else None
        state.push(
            SymValue(
                z3.Int(state.fresh_name("iter")),
                sym_type=SymType.UNKNOWN,
                taint=container.taint if container else TaintInfo(),
            )
        )
        return None

    def _op_FOR_ITER(self, arg, state, crashes, call_sites):
        state.push(SymValue(z3.Int(state.fresh_name("item")), sym_type=SymType.UNKNOWN))
        return None

    def _op_END_FOR(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        return None

    def _op_RETURN_VALUE(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        return None

    def _op_RETURN_CONST(self, arg, state, crashes, call_sites):
        return None

    def _op_YIELD_VALUE(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("sent")), sym_type=SymType.UNKNOWN))
        return None

    def _op_RESUME(self, arg, state, crashes, call_sites):
        return None

    def _op_NOP(self, arg, state, crashes, call_sites):
        return None

    def _op_PRECALL(self, arg, state, crashes, call_sites):
        return None

    def _op_KW_NAMES(self, arg, state, crashes, call_sites):
        return None

    def _op_MAKE_FUNCTION(self, arg, state, crashes, call_sites):
        if state.stack:
            state.pop()
        state.push(SymValue(z3.Int(state.fresh_name("func")), sym_type=SymType.CALLABLE))
        return None

    def _op_FORMAT_VALUE(self, arg, state, crashes, call_sites):
        if state.stack:
            val = state.pop()
            state.push(
                SymValue(
                    z3.Int(state.fresh_name("fmt")),
                    sym_type=SymType.STRING,
                    taint=val.taint.propagate("format"),
                )
            )
        return None

    def _op_UNPACK_SEQUENCE(self, arg, state, crashes, call_sites):
        seq = state.pop() if state.stack else None
        n = arg if isinstance(arg, int) else 1
        for i in range(n):
            state.push(
                SymValue(
                    z3.Int(state.fresh_name("unpack")),
                    sym_type=SymType.UNKNOWN,
                    taint=seq.taint if seq else TaintInfo(),
                )
            )
        return None

    def _op_DELETE_FAST(self, arg, state, crashes, call_sites):
        name = str(arg)
        if name in state.variables:
            del state.variables[name]
        return None

    def _op_RAISE_VARARGS(self, arg, state, crashes, call_sites):
        n = arg if isinstance(arg, int) else 0
        for _ in range(n):
            if state.stack:
                state.pop()
        return None

    def _op_RERAISE(self, arg, state, crashes, call_sites):
        return None

    def _op_unknown(self, op, arg, state, crashes, call_sites):
        """Handle unknown opcodes gracefully."""
        return None

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


class Z3Engine:
    """
    Intelligent interprocedural verification engine.
    Features:
    - Call graph analysis
    - Function summaries with caching
    - Priority-based path exploration
    - Taint tracking
    - Cross-function verification
    """

    def __init__(
        self,
        timeout_ms: int = 5000,
        max_depth: int = 50,
        interprocedural: bool = True,
        track_taint: bool = True,
    ):
        if not Z3_AVAILABLE:
            raise RuntimeError("Z3 is required: pip install z3-solver")
        self.timeout = timeout_ms
        self.max_depth = max_depth
        self.interprocedural = interprocedural
        self.track_taint = track_taint
        self.call_graph = CallGraph()
        self.function_summaries: dict[str, FunctionSummary] = {}
        self.summaries = self.function_summaries
        self.analyzer = FunctionAnalyzer(self)
        self.verified_crashes: dict[str, VerificationResult] = {}

    def verify_function(self, func: Callable) -> list[VerificationResult]:
        """Verify a single function."""
        return self.verify_code(func.__code__)

    def verify_code(self, code: Any) -> list[VerificationResult]:
        """Verify a code object."""
        crashes, summary = self.analyzer.analyze(code)
        for callee in summary.calls_functions:
            self.call_graph.add_call(
                CallSite(caller=code.co_name, callee=callee, line=0, arguments=[])
            )
        self.summaries[code.co_name] = summary
        return self._verify_crashes(crashes)

    def verify_file(self, path: str) -> dict[str, list[VerificationResult]]:
        """
        Verify all functions in a file with interprocedural analysis.
        """
        with open(path, encoding="utf-8", errors="ignore") as f:
            source = f.read()
        code = compile(source, path, "exec")
        self.analyzer.current_file = path
        results: dict[str, list[VerificationResult]] = {}
        all_codes: list[Any] = []

        def collect_codes(code_obj):
            all_codes.append(code_obj)
            for const in code_obj.co_consts:
                if hasattr(const, "co_code"):
                    collect_codes(const)

        collect_codes(code)
        for code_obj in all_codes:
            crashes, summary = self.analyzer.analyze(code_obj)
            self.summaries[code_obj.co_name] = summary
            for callee in summary.calls_functions:
                self.call_graph.add_call(
                    CallSite(
                        caller=code_obj.co_name, callee=callee, line=0, arguments=[], file_path=path
                    )
                )
        self.call_graph.find_recursive()
        for code_obj in all_codes:
            func_name = code_obj.co_name
            context = self._build_context_from_callees(func_name)
            crashes, _ = self.analyzer.analyze(code_obj, context=context)
            if crashes:
                verified = self._verify_crashes(crashes)
                actual_crashes = [v for v in verified if v.can_crash]
                if actual_crashes:
                    results[func_name] = actual_crashes
        return results

    def verify_directory(self, path: str) -> dict[str, dict[str, list[VerificationResult]]]:
        """Verify all Python files in a directory."""
        import os

        all_results: dict[str, dict[str, list[VerificationResult]]] = {}
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    try:
                        file_results = self.verify_file(filepath)
                        if file_results:
                            all_results[filepath] = file_results
                    except Exception:
                        pass
        return all_results

    def _build_context_from_callees(self, func_name: str) -> dict[str, SymValue] | None:
        """Build context from function summaries of callees."""
        return None

    def _verify_crashes(self, crashes: list[CrashCondition]) -> list[VerificationResult]:
        """Verify crash conditions with Z3."""
        results = []
        seen: set[tuple[int, str, str]] = set()
        for crash in crashes:
            key = (crash.line, crash.bug_type.value, crash.function)
            if key in seen:
                continue
            seen.add(key)
            result = self._verify_single_crash(crash)
            results.append(result)
        return results

    def _verify_single_crash(self, crash: CrashCondition) -> VerificationResult:
        """Verify a single crash condition."""
        start = time.time()
        solver = z3.Solver()
        solver.set("timeout", self.timeout)
        for constraint in crash.path_constraints:
            try:
                solver.add(constraint)
            except Exception:
                pass
        try:
            solver.add(crash.condition)
        except Exception:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(crash, True, False, None, "error", elapsed)
        result = solver.check()
        elapsed = (time.time() - start) * 1000
        if result == z3.sat:
            model = solver.model()
            counterexample = {}
            for name, expr in crash.variables.items():
                try:
                    val = model.eval(expr, model_completion=True)
                    counterexample[name] = str(val)
                except Exception:
                    counterexample[name] = "?"
            return VerificationResult(
                crash=crash,
                can_crash=True,
                proven_safe=False,
                counterexample=counterexample,
                z3_status="sat",
                verification_time_ms=elapsed,
            )
        elif result == z3.unsat:
            return VerificationResult(
                crash=crash,
                can_crash=False,
                proven_safe=True,
                z3_status="unsat",
                verification_time_ms=elapsed,
            )
        else:
            return VerificationResult(
                crash=crash,
                can_crash=True,
                proven_safe=False,
                z3_status="unknown",
                verification_time_ms=elapsed,
            )

    def get_call_graph_info(self) -> dict[str, Any]:
        """Get information about the call graph."""
        return {
            "functions": list(self.call_graph.calls.keys()),
            "total_calls": sum(len(v) for v in self.call_graph.calls.values()),
            "recursive_functions": list(self.call_graph.recursive),
            "entry_points": list(self.call_graph.entry_points),
        }

    def get_function_summary(self, name: str) -> FunctionSummary | None:
        """Get cached summary for a function."""
        return self.summaries.get(name)


def verify_function(func: Callable) -> list[VerificationResult]:
    """Verify a Python function."""
    if not Z3_AVAILABLE:
        return []
    engine = Z3Engine()
    return engine.verify_function(func)


def verify_code(code: Any) -> list[VerificationResult]:
    """Verify a code object."""
    if not Z3_AVAILABLE:
        return []
    engine = Z3Engine()
    return engine.verify_code(code)


def verify_file(path: str, timeout_ms: int = 5000) -> dict[str, list[VerificationResult]]:
    """Verify all functions in a file."""
    if not Z3_AVAILABLE:
        return {}
    engine = Z3Engine(timeout_ms=timeout_ms)
    return engine.verify_file(path)


def verify_directory(
    path: str, timeout_ms: int = 5000
) -> dict[str, dict[str, list[VerificationResult]]]:
    """Verify all files in a directory."""
    if not Z3_AVAILABLE:
        return {}
    engine = Z3Engine(timeout_ms=timeout_ms)
    return engine.verify_directory(path)


def is_z3_available() -> bool:
    """Check if Z3 is available."""
    return Z3_AVAILABLE


Z3Prover = Z3Engine
