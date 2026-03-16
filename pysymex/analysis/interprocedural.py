"""Inter-procedural analysis for pysymex.
This module provides support for analyzing function calls symbolically,
building call graphs, and performing whole-program analysis.
"""

from __future__ import annotations

import dis
import inspect
import types
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
    Any,
    cast,
)

import z3

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.execution.executor import ExecutionResult


class CallType(Enum):
    """Types of function calls."""

    DIRECT = auto()
    INDIRECT = auto()
    BUILTIN = auto()
    METHOD = auto()
    CONSTRUCTOR = auto()
    LAMBDA = auto()
    CLOSURE = auto()


@dataclass
class CallSite:
    """Represents a function call site in the code."""

    caller: str
    callee: str | None
    call_type: CallType
    pc: int
    line_number: int | None = None
    arguments: list[object] = field(default_factory=list[object])
    return_type: str | None = None
    is_recursive: bool = False
    depth: int = 0


@dataclass
class FunctionSummary:
    """Summary of a function's symbolic behavior.
    Function summaries enable modular analysis by capturing
    the essential effects of a function without re-analyzing it.
    """

    name: str
    parameters: list[str]
    preconditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    postconditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    return_expr: z3.ExprRef | None = None
    modifies_globals: set[str] = field(default_factory=set[str])
    raises_exceptions: set[str] = field(default_factory=set[str])
    is_pure: bool = True
    is_total: bool = True
    max_depth_analyzed: int = 0

    def apply(
        self,
        args: list[object],
        state: VMState,
    ) -> tuple[Any, list[z3.BoolRef]]:
        """Apply this summary to concrete/symbolic arguments.
        Returns the symbolic return value and additional constraints.
        """
        subst: dict[z3.ExprRef, z3.ExprRef] = {}
        for param, arg in zip(self.parameters, args, strict=False):
            if hasattr(arg, "z3_expr"):
                subst[z3.Const(param, arg.z3_expr.sort())] = arg.z3_expr
        if self.return_expr is not None:
            result = z3.substitute(self.return_expr, list(subst.items()))
        else:
            result = None
        constraints: list[z3.BoolRef] = []
        for pre in self.preconditions:
            constraints.append(cast("z3.BoolRef", z3.substitute(pre, list(subst.items()))))
        return result, constraints


class CallGraph:
    """Represents the call graph of analyzed functions."""

    def __init__(self):
        self._nodes: set[str] = set()
        self._edges: dict[str, set[str]] = {}
        self._call_sites: dict[tuple[str, str], list[CallSite]] = {}
        self._summaries: dict[str, FunctionSummary] = {}

    def add_function(self, name: str) -> None:
        """Add a function node to the graph."""
        self._nodes.add(name)
        if name not in self._edges:
            self._edges[name] = set()

    def add_call(self, caller: str, callee: str, site: CallSite) -> None:
        """Add a call edge to the graph."""
        self.add_function(caller)
        self.add_function(callee)
        self._edges[caller].add(callee)
        key = (caller, callee)
        if key not in self._call_sites:
            self._call_sites[key] = []
        self._call_sites[key].append(site)

    def get_callees(self, caller: str) -> set[str]:
        """Get all functions called by the given function."""
        return self._edges.get(caller, set())

    def get_callers(self, callee: str) -> set[str]:
        """Get all functions that call the given function."""
        return {caller for caller, callees in self._edges.items() if callee in callees}

    def get_call_sites(self, caller: str, callee: str) -> list[CallSite]:
        """Get all call sites between two functions."""
        return self._call_sites.get((caller, callee), [])

    def is_recursive(self, func: str) -> bool:
        """Check if a function is directly or indirectly recursive."""
        visited: set[str] = set()
        stack = [func]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for callee in self.get_callees(current):
                if callee == func:
                    return True
                stack.append(callee)
        return False

    def topological_order(self) -> list[str]:
        """Return functions in topological order (callees before callers).
        Useful for bottom-up analysis where we analyze called functions first.
        """
        in_degree: dict[str, int] = dict.fromkeys(self._nodes, 0)
        for callees in self._edges.values():
            for callee in callees:
                if callee in in_degree:
                    in_degree[callee] += 1
        queue: list[str] = [n for n, d in in_degree.items() if d == 0]
        result: list[str] = []
        while queue:
            node = queue.pop(0)
            result.append(node)
            for callee in self._edges.get(node, set()):
                if callee in in_degree:
                    in_degree[callee] -= 1
                    if in_degree[callee] == 0:
                        queue.append(callee)
        result.extend(n for n in self._nodes if n not in result)
        result.reverse()
        return result

    def add_summary(self, name: str, summary: FunctionSummary) -> None:
        """Store a function summary."""
        self._summaries[name] = summary

    def get_summary(self, name: str) -> FunctionSummary | None:
        """Retrieve a function summary."""
        return self._summaries.get(name)

    def to_dot(self) -> str:
        """Export call graph to DOT format for visualization."""
        lines = ["digraph CallGraph {"]
        lines.append("  rankdir=TB;")
        lines.append("  node [shape=box];")
        for node in self._nodes:
            style = ""
            if self.is_recursive(node):
                style = " [style=filled, fillcolor=yellow]"
            lines.append(f'  "{node }"{style };')
        for caller, callees in self._edges.items():
            for callee in callees:
                lines.append(f'  "{caller }" -> "{callee }";')
        lines.append("}")
        return "\n".join(lines)


class InterproceduralAnalyzer:
    """Performs inter-procedural symbolic analysis.
    This analyzer builds call graphs and function summaries
    to analyze programs with multiple functions.
    """

    def __init__(
        self,
        max_inline_depth: int = 3,
        max_recursion_depth: int = 5,
        use_summaries: bool = True,
    ):
        self.max_inline_depth = max_inline_depth
        self.max_recursion_depth = max_recursion_depth
        self.use_summaries = use_summaries
        self.call_graph = CallGraph()
        self._function_cache: dict[str, types.FunctionType] = {}
        self._analysis_stack: list[str] = []

    def analyze_module(
        self,
        module: types.ModuleType,
        entry_points: list[str] | None = None,
    ) -> dict[str, ExecutionResult]:
        """Analyze all functions in a module.
        Args:
            module: The module to analyze
            entry_points: Specific functions to analyze (or all if None)
        Returns:
            Dictionary mapping function names to analysis results
        """
        from pysymex.execution.executor import SymbolicExecutor

        functions: dict[str, types.FunctionType] = {}
        for name, obj in inspect.getmembers(module):
            if inspect.isfunction(obj) and obj.__module__ == module.__name__:
                functions[name] = obj
                self._function_cache[name] = obj
        for name, func in functions.items():
            self._extract_calls(name, func)
        if entry_points:
            to_analyze = entry_points
        else:
            to_analyze = self.call_graph.topological_order()
        results: dict[str, ExecutionResult] = {}
        executor = SymbolicExecutor()
        for name in to_analyze:
            if name not in functions:
                continue
            func = functions[name]
            self._analysis_stack.append(name)
            try:
                result = executor.execute_function(func)
                results[name] = result
                if self.use_summaries:
                    summary = self._generate_summary(name, func, result)
                    self.call_graph.add_summary(name, summary)
            finally:
                self._analysis_stack.pop()
        return results

    def _extract_calls(self, func_name: str, func: types.FunctionType) -> None:
        """Extract call sites from a function's bytecode."""
        self.call_graph.add_function(func_name)
        instructions = _cached_get_instructions(func.__code__)
        for i, instr in enumerate(instructions):
            if instr.opname in ("CALL", "CALL_FUNCTION", "CALL_METHOD"):
                callee = self._resolve_callee(instructions, i)
                if callee:
                    call_type = CallType.DIRECT
                    if callee.startswith("<"):
                        call_type = CallType.BUILTIN
                    site = CallSite(
                        caller=func_name,
                        callee=callee,
                        call_type=call_type,
                        pc=i,
                        line_number=getattr(instr, "starts_line", None),
                    )
                    self.call_graph.add_call(func_name, callee, site)

    def _resolve_callee(
        self,
        instructions: Sequence[dis.Instruction],
        call_index: int,
    ) -> str | None:
        """Try to resolve the name of the called function."""
        for i in range(call_index - 1, max(0, call_index - 10), -1):
            instr = instructions[i]
            if instr.opname in ("LOAD_GLOBAL", "LOAD_NAME") or instr.opname == "LOAD_ATTR":
                return str(instr.argval)
            elif instr.opname == "LOAD_FAST":
                return None
        return None

    def _generate_summary(
        self,
        name: str,
        func: types.FunctionType,
        result: ExecutionResult,
    ) -> FunctionSummary:
        """Generate a function summary from analysis results."""
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        summary = FunctionSummary(
            name=name,
            parameters=params,
        )
        for issue in result.issues:
            if issue.kind.name == "DIVISION_BY_ZERO":
                pass
            elif issue.kind.name == "ASSERTION_ERROR":
                summary.is_total = False
        code = func.__code__
        if code.co_flags & 0x10:
            summary.is_pure = False
        summary.max_depth_analyzed = result.paths_explored
        return summary

    def should_inline(self, callee: str, depth: int) -> bool:
        """Determine if a function call should be inlined for analysis."""
        if depth > self.max_inline_depth:
            return False
        if self.call_graph.is_recursive(callee):
            return depth < self.max_recursion_depth
        if self.use_summaries and self.call_graph.get_summary(callee):
            return False
        return True

    def get_call_graph_dot(self) -> str:
        """Get the call graph in DOT format."""
        return self.call_graph.to_dot()


@dataclass
class CallContext:
    """Represents calling context for context-sensitive analysis."""

    call_string: tuple[str, ...]
    max_length: int = 3

    def extend(self, call_site: str) -> CallContext:
        """Create new context with additional call site."""
        new_string = (*self.call_string, call_site)
        if len(new_string) > self.max_length:
            new_string = new_string[-self.max_length :]
        return CallContext(new_string, self.max_length)

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash(self.call_string)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallContext):
            return False
        return self.call_string == other.call_string


class ContextSensitiveAnalyzer:
    """Context-sensitive inter-procedural analyzer.
    Uses k-CFA (Control Flow Analysis) style context sensitivity
    where contexts are distinguished by the last k call sites.
    """

    def __init__(self, k: int = 2):
        self.k = k
        self._results: dict[tuple[str, CallContext], Any] = {}

    def analyze_with_context(
        self,
        func: Callable[..., object],
        context: CallContext,
    ) -> object:
        """Analyze a function in a specific calling context."""
        key = (func.__name__, context)
        if key in self._results:
            return self._results[key]
        from pysymex.execution.executor import SymbolicExecutor

        executor = SymbolicExecutor()
        result = executor.execute_function(func)
        self._results[key] = result
        return result


__all__ = [
    "CallContext",
    "CallGraph",
    "CallSite",
    "CallType",
    "ContextSensitiveAnalyzer",
    "FunctionSummary",
    "InterproceduralAnalyzer",
]
