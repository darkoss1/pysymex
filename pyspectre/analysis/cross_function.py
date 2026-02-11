"""
Cross-Function Analysis for PySpectre.
This module provides cross-function analysis capabilities including:
- Call graph construction
- Function summaries with effects
- Context-sensitive analysis
- Escape analysis
- Side effect tracking
"""

from __future__ import annotations
import dis
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, Flag, auto
from typing import (
    Any,
)
from .type_inference import PyType, TypeEnvironment


class Effect(Flag):
    """Side effects that a function may have."""

    NONE = 0
    READ_LOCAL = auto()
    WRITE_LOCAL = auto()
    READ_GLOBAL = auto()
    WRITE_GLOBAL = auto()
    READ_HEAP = auto()
    WRITE_HEAP = auto()
    ALLOCATE = auto()
    READ_FILE = auto()
    WRITE_FILE = auto()
    READ_NETWORK = auto()
    WRITE_NETWORK = auto()
    READ_STDIN = auto()
    WRITE_STDOUT = auto()
    RAISE = auto()
    EXIT = auto()
    FORK = auto()
    PURE = NONE
    READ_ANY = READ_LOCAL | READ_GLOBAL | READ_HEAP
    WRITE_ANY = WRITE_LOCAL | WRITE_GLOBAL | WRITE_HEAP
    IO = READ_FILE | WRITE_FILE | READ_NETWORK | WRITE_NETWORK
    IMPURE = READ_ANY | WRITE_ANY | IO | RAISE


@dataclass(frozen=True)
class EffectSummary:
    """Summary of effects for a function."""

    effects: Effect = Effect.NONE
    reads_globals: frozenset[str] = frozenset()
    reads_attributes: frozenset[str] = frozenset()
    writes_globals: frozenset[str] = frozenset()
    writes_attributes: frozenset[str] = frozenset()
    may_raise: frozenset[str] = frozenset()
    allocates: frozenset[str] = frozenset()

    @property
    def is_pure(self) -> bool:
        """Check if function is pure (no side effects)."""
        return self.effects == Effect.NONE

    @property
    def is_read_only(self) -> bool:
        """Check if function only reads."""
        return not (self.effects & Effect.WRITE_ANY)

    def merge_with(self, other: EffectSummary) -> EffectSummary:
        """Merge two effect summaries."""
        return EffectSummary(
            effects=self.effects | other.effects,
            reads_globals=self.reads_globals | other.reads_globals,
            reads_attributes=self.reads_attributes | other.reads_attributes,
            writes_globals=self.writes_globals | other.writes_globals,
            writes_attributes=self.writes_attributes | other.writes_attributes,
            may_raise=self.may_raise | other.may_raise,
            allocates=self.allocates | other.allocates,
        )


@dataclass
class CallSiteInfo:
    """Information about a call site."""

    caller: str
    callee: str
    line: int
    pc: int
    arg_count: int = 0
    has_kwargs: bool = False
    has_varargs: bool = False
    is_method_call: bool = False
    is_static: bool = False
    is_super_call: bool = False
    is_dynamic: bool = False
    possible_callees: set[str] = field(default_factory=set)


@dataclass
class CallGraphNode:
    """Node in the call graph representing a function."""

    name: str
    qualified_name: str
    callees: list[CallSiteInfo] = field(default_factory=list)
    callers: set[str] = field(default_factory=set)
    is_recursive: bool = False
    is_entry_point: bool = False
    type_env: TypeEnvironment | None = None
    effect_summary: EffectSummary | None = None


class CallGraph:
    """
    Call graph representing function call relationships.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, CallGraphNode] = {}
        self.entry_points: set[str] = set()

    def add_function(self, name: str, qualified_name: str = "") -> CallGraphNode:
        """Add a function to the call graph."""
        if name not in self.nodes:
            self.nodes[name] = CallGraphNode(
                name=name,
                qualified_name=qualified_name or name,
            )
        return self.nodes[name]

    def add_call(
        self,
        caller: str,
        callee: str,
        line: int,
        pc: int,
        **kwargs: Any,
    ) -> None:
        """Add a call edge to the graph."""
        caller_node = self.add_function(caller)
        callee_node = self.add_function(callee)
        call_site = CallSiteInfo(
            caller=caller,
            callee=callee,
            line=line,
            pc=pc,
            **kwargs,
        )
        caller_node.callees.append(call_site)
        callee_node.callers.add(caller)

    def get_callees(self, func: str) -> list[str]:
        """Get all functions called by a function."""
        if func not in self.nodes:
            return []
        return [cs.callee for cs in self.nodes[func].callees]

    def get_callers(self, func: str) -> set[str]:
        """Get all functions that call a function."""
        if func not in self.nodes:
            return set()
        return self.nodes[func].callers

    def find_recursive(self) -> set[str]:
        """Find all recursive functions."""
        recursive: set[str] = set()
        for name in self.nodes:
            if self._is_recursive(name, set()):
                recursive.add(name)
                self.nodes[name].is_recursive = True
        return recursive

    def _is_recursive(self, func: str, visited: set[str]) -> bool:
        """Check if a function is (mutually) recursive."""
        if func in visited:
            return True
        visited = visited | {func}
        for callee in self.get_callees(func):
            if callee in visited or self._is_recursive(callee, visited):
                return True
        return False

    def topological_order(self) -> list[str]:
        """Get functions in topological order (callees before callers)."""
        in_degree: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            for cs in node.callees:
                in_degree[cs.callee] += 1
        queue = [name for name in self.nodes if in_degree[name] == 0]
        result = []
        while queue:
            func = queue.pop(0)
            result.append(func)
            for caller in self.get_callers(func):
                in_degree[caller] -= 1
                if in_degree[caller] == 0:
                    queue.append(caller)
        for name in self.nodes:
            if name not in result:
                result.append(name)
        return result

    def get_reachable(self, from_func: str) -> set[str]:
        """Get all functions reachable from a starting function."""
        reachable: set[str] = set()
        worklist = [from_func]
        while worklist:
            func = worklist.pop()
            if func in reachable:
                continue
            reachable.add(func)
            worklist.extend(self.get_callees(func))
        return reachable


class CallGraphBuilder:
    """
    Builds a call graph from bytecode.
    """

    def __init__(self) -> None:
        self.call_graph = CallGraph()

    def build_from_module(self, module_code: Any) -> CallGraph:
        """Build call graph from a module's code object."""
        self.call_graph = CallGraph()
        self._process_code(module_code, "<module>")
        self._find_functions(module_code)
        if "<module>" in self.call_graph.nodes:
            self.call_graph.nodes["<module>"].is_entry_point = True
            self.call_graph.entry_points.add("<module>")
        self.call_graph.find_recursive()
        return self.call_graph

    def _find_functions(self, code: Any, prefix: str = "") -> None:
        """Find all functions in a code object."""
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                func_name = const.co_name
                qualified_name = f"{prefix}.{func_name}" if prefix else func_name
                self.call_graph.add_function(func_name, qualified_name)
                self._process_code(const, func_name)
                self._find_functions(const, qualified_name)

    def _process_code(self, code: Any, func_name: str) -> None:
        """Process a code object for call sites."""
        instructions = list(dis.get_instructions(code))
        current_line = code.co_firstlineno
        stack_items: list[str] = []
        for i, instr in enumerate(instructions):
            if instr.starts_line:
                current_line = instr.starts_line
            opname = instr.opname
            arg = instr.argval
            if opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                stack_items.append(str(arg))
            elif opname == "LOAD_CONST":
                stack_items.append(f"const:{arg}")
            elif opname == "LOAD_ATTR":
                if stack_items:
                    base = stack_items.pop()
                    stack_items.append(f"{base}.{arg}")
                else:
                    stack_items.append(f"?.{arg}")
            elif opname == "LOAD_METHOD":
                if stack_items:
                    base = stack_items.pop()
                    stack_items.append(f"{base}.{arg}")
                else:
                    stack_items.append(f"?.{arg}")
            elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                arg_count = arg if arg is not None else 0
                for _ in range(arg_count):
                    if stack_items:
                        stack_items.pop()
                callee = stack_items.pop() if stack_items else "?"
                is_method = "." in callee and not callee.startswith("const:")
                self.call_graph.add_call(
                    caller=func_name,
                    callee=callee,
                    line=current_line,
                    pc=instr.offset,
                    arg_count=arg_count,
                    is_method_call=is_method,
                    is_dynamic=callee.startswith("?"),
                )
                stack_items.append(f"result:{callee}")
            elif opname in {"CALL_FUNCTION_KW", "CALL_FUNCTION_EX"}:
                if stack_items:
                    callee = stack_items.pop()
                    self.call_graph.add_call(
                        caller=func_name,
                        callee=callee,
                        line=current_line,
                        pc=instr.offset,
                        has_kwargs=True,
                    )
                stack_items.append("result:?")
            elif opname == "POP_TOP":
                if stack_items:
                    stack_items.pop()
            elif opname == "DUP_TOP":
                if stack_items:
                    stack_items.append(stack_items[-1])
            elif opname == "ROT_TWO":
                if len(stack_items) >= 2:
                    stack_items[-1], stack_items[-2] = stack_items[-2], stack_items[-1]
            elif opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL"}:
                if stack_items:
                    stack_items.pop()
            elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET"}:
                count = arg or 0
                for _ in range(count):
                    if stack_items:
                        stack_items.pop()
                stack_items.append(opname.replace("BUILD_", "").lower())
            elif opname == "BUILD_MAP":
                count = arg or 0
                for _ in range(count * 2):
                    if stack_items:
                        stack_items.pop()
                stack_items.append("dict")
            elif opname in {"BINARY_OP", "BINARY_SUBSCR", "COMPARE_OP"}:
                if len(stack_items) >= 2:
                    stack_items.pop()
                    stack_items.pop()
                stack_items.append("expr")
            elif opname.startswith("UNARY_"):
                if stack_items:
                    stack_items.pop()
                stack_items.append("expr")


class EffectAnalyzer:
    """
    Analyzes functions for side effects.
    """

    PURE_FUNCTIONS: set[str] = {
        "len",
        "str",
        "int",
        "float",
        "bool",
        "bytes",
        "list",
        "dict",
        "set",
        "tuple",
        "frozenset",
        "range",
        "enumerate",
        "zip",
        "map",
        "filter",
        "sorted",
        "reversed",
        "min",
        "max",
        "sum",
        "abs",
        "round",
        "pow",
        "divmod",
        "chr",
        "ord",
        "hex",
        "oct",
        "bin",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "type",
        "id",
        "hash",
        "repr",
        "ascii",
        "format",
        "vars",
    }
    IO_FUNCTIONS: set[str] = {
        "print",
        "input",
        "open",
        "read",
        "write",
        "readline",
        "readlines",
        "writelines",
    }

    def __init__(self) -> None:
        self.cache: dict[str, EffectSummary] = {}

    def analyze_function(self, code: Any, name: str = "") -> EffectSummary:
        """Analyze a function for effects."""
        if name in self.cache:
            return self.cache[name]
        effects = Effect.NONE
        reads_globals: set[str] = set()
        writes_globals: set[str] = set()
        reads_attributes: set[str] = set()
        writes_attributes: set[str] = set()
        may_raise: set[str] = set()
        allocates: set[str] = set()
        for instr in dis.get_instructions(code):
            opname = instr.opname
            arg = instr.argval
            if opname == "LOAD_GLOBAL":
                effects |= Effect.READ_GLOBAL
                reads_globals.add(str(arg))
            elif opname == "STORE_GLOBAL":
                effects |= Effect.WRITE_GLOBAL
                writes_globals.add(str(arg))
            elif opname == "DELETE_GLOBAL":
                effects |= Effect.WRITE_GLOBAL
                writes_globals.add(str(arg))
            elif opname == "LOAD_ATTR":
                effects |= Effect.READ_HEAP
                reads_attributes.add(str(arg))
            elif opname == "STORE_ATTR":
                effects |= Effect.WRITE_HEAP
                writes_attributes.add(str(arg))
            elif opname == "DELETE_ATTR":
                effects |= Effect.WRITE_HEAP
                writes_attributes.add(str(arg))
            elif opname == "BINARY_SUBSCR":
                effects |= Effect.READ_HEAP
            elif opname == "STORE_SUBSCR":
                effects |= Effect.WRITE_HEAP
            elif opname == "DELETE_SUBSCR":
                effects |= Effect.WRITE_HEAP
            elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET", "BUILD_MAP"}:
                effects |= Effect.ALLOCATE
                allocates.add(opname.replace("BUILD_", "").lower())
            elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                effects |= Effect.READ_LOCAL
            elif opname == "RAISE_VARARGS":
                effects |= Effect.RAISE
                may_raise.add("Exception")
        summary = EffectSummary(
            effects=effects,
            reads_globals=frozenset(reads_globals),
            writes_globals=frozenset(writes_globals),
            reads_attributes=frozenset(reads_attributes),
            writes_attributes=frozenset(writes_attributes),
            may_raise=frozenset(may_raise),
            allocates=frozenset(allocates),
        )
        self.cache[name] = summary
        return summary

    def analyze_with_call_graph(
        self,
        call_graph: CallGraph,
        code_objects: dict[str, Any],
    ) -> dict[str, EffectSummary]:
        """Analyze all functions with call graph for interprocedural effects."""
        summaries: dict[str, EffectSummary] = {}
        order = call_graph.topological_order()
        for func_name in order:
            if func_name not in code_objects:
                summaries[func_name] = self._get_builtin_effects(func_name)
                continue
            code = code_objects[func_name]
            local_effects = self.analyze_function(code, func_name)
            node = call_graph.nodes.get(func_name)
            if node:
                for call_site in node.callees:
                    callee = call_site.callee
                    if callee in summaries:
                        local_effects = local_effects.merge_with(summaries[callee])
            summaries[func_name] = local_effects
        return summaries

    def _get_builtin_effects(self, func_name: str) -> EffectSummary:
        """Get effects for built-in/external functions."""
        base_name = func_name.split(".")[-1]
        if base_name in self.PURE_FUNCTIONS:
            return EffectSummary(effects=Effect.NONE)
        if base_name in self.IO_FUNCTIONS:
            return EffectSummary(effects=Effect.IO | Effect.RAISE)
        return EffectSummary(effects=Effect.IMPURE)


class EscapeState(Enum):
    """Escape state of an allocated object."""

    NO_ESCAPE = auto()
    ARG_ESCAPE = auto()
    RETURN_ESCAPE = auto()
    GLOBAL_ESCAPE = auto()


@dataclass
class EscapeInfo:
    """Information about object escape."""

    state: EscapeState
    escape_sites: list[tuple[int, str]] = field(default_factory=list)


class EscapeAnalyzer:
    """
    Analyzes object escape to determine allocation optimizations.
    """

    def analyze_function(self, code: Any) -> dict[int, EscapeInfo]:
        """Analyze object escape in a function."""
        allocations: dict[int, EscapeInfo] = {}
        stack: list[int | None] = []
        instructions = list(dis.get_instructions(code))
        current_line = code.co_firstlineno
        for instr in instructions:
            if instr.starts_line:
                current_line = instr.starts_line
            opname = instr.opname
            arg = instr.argval
            pc = instr.offset
            if opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET", "BUILD_MAP"}:
                count = arg or 0
                for _ in range(count if opname != "BUILD_MAP" else count * 2):
                    if stack:
                        stack.pop()
                allocations[pc] = EscapeInfo(state=EscapeState.NO_ESCAPE)
                stack.append(pc)
            elif opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
                stack.append(None)
            elif opname == "LOAD_CONST":
                stack.append(None)
            elif opname in {"STORE_FAST", "STORE_NAME", "STORE_DEREF"}:
                if stack:
                    stack.pop()
            elif opname == "STORE_GLOBAL":
                if stack:
                    alloc_pc = stack.pop()
                    if alloc_pc is not None and alloc_pc in allocations:
                        allocations[alloc_pc].state = EscapeState.GLOBAL_ESCAPE
                        allocations[alloc_pc].escape_sites.append(
                            (current_line, f"stored to global {arg}")
                        )
            elif opname == "STORE_ATTR":
                if len(stack) >= 2:
                    alloc_pc = stack.pop()
                    stack.pop()
                    if alloc_pc is not None and alloc_pc in allocations:
                        allocations[alloc_pc].state = EscapeState.GLOBAL_ESCAPE
                        allocations[alloc_pc].escape_sites.append(
                            (current_line, f"stored to attribute {arg}")
                        )
            elif opname == "RETURN_VALUE":
                if stack:
                    alloc_pc = stack.pop()
                    if alloc_pc is not None and alloc_pc in allocations:
                        if allocations[alloc_pc].state == EscapeState.NO_ESCAPE:
                            allocations[alloc_pc].state = EscapeState.RETURN_ESCAPE
                            allocations[alloc_pc].escape_sites.append((current_line, "returned"))
            elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                arg_count = arg if arg is not None else 0
                for _ in range(arg_count):
                    if stack:
                        alloc_pc = stack.pop()
                        if alloc_pc is not None and alloc_pc in allocations:
                            if allocations[alloc_pc].state == EscapeState.NO_ESCAPE:
                                allocations[alloc_pc].state = EscapeState.ARG_ESCAPE
                                allocations[alloc_pc].escape_sites.append(
                                    (current_line, "passed as argument")
                                )
                if stack:
                    stack.pop()
                stack.append(None)
            elif opname.startswith("BINARY_") or opname == "COMPARE_OP":
                if len(stack) >= 2:
                    stack.pop()
                    stack.pop()
                stack.append(None)
            elif opname.startswith("UNARY_"):
                if stack:
                    stack.pop()
                stack.append(None)
            elif opname == "POP_TOP":
                if stack:
                    stack.pop()
            elif opname == "DUP_TOP":
                if stack:
                    stack.append(stack[-1])
        return allocations


@dataclass(frozen=True)
class CallContext:
    """
    Context for context-sensitive analysis.
    Uses call-string approach: track the last k call sites.
    """

    call_string: tuple[tuple[str, int], ...] = ()

    def extend(self, caller: str, pc: int, k: int = 2) -> CallContext:
        """Extend context with a new call site."""
        new_string = self.call_string + ((caller, pc),)
        if len(new_string) > k:
            new_string = new_string[-k:]
        return CallContext(new_string)

    def __str__(self) -> str:
        if not self.call_string:
            return "<entry>"
        return " -> ".join(f"{caller}@{pc}" for caller, pc in self.call_string)


@dataclass
class ContextSensitiveSummary:
    """Summary for a function under a specific context."""

    context: CallContext
    function: str
    type_env: TypeEnvironment | None = None
    effect_summary: EffectSummary | None = None
    param_types: dict[str, PyType] = field(default_factory=dict)
    return_type: PyType | None = None


class ContextSensitiveAnalyzer:
    """
    Context-sensitive interprocedural analysis.
    """

    def __init__(self, k: int = 2) -> None:
        self.k = k
        self.summaries: dict[tuple[str, CallContext], ContextSensitiveSummary] = {}
        self.call_graph: CallGraph | None = None

    def analyze(
        self,
        call_graph: CallGraph,
        code_objects: dict[str, Any],
    ) -> dict[tuple[str, CallContext], ContextSensitiveSummary]:
        """Run context-sensitive analysis."""
        self.call_graph = call_graph
        self.summaries = {}
        for entry in call_graph.entry_points:
            if entry in code_objects:
                self._analyze_function(
                    entry,
                    code_objects[entry],
                    CallContext(),
                    code_objects,
                )
        return self.summaries

    def _analyze_function(
        self,
        func_name: str,
        code: Any,
        context: CallContext,
        code_objects: dict[str, Any],
    ) -> ContextSensitiveSummary:
        """Analyze a function under a specific context."""
        key = (func_name, context)
        if key in self.summaries:
            return self.summaries[key]
        summary = ContextSensitiveSummary(
            context=context,
            function=func_name,
        )
        self.summaries[key] = summary
        effect_analyzer = EffectAnalyzer()
        summary.effect_summary = effect_analyzer.analyze_function(code, func_name)
        if self.call_graph:
            node = self.call_graph.nodes.get(func_name)
            if node:
                for call_site in node.callees:
                    callee = call_site.callee
                    if callee in code_objects:
                        new_context = context.extend(func_name, call_site.pc, self.k)
                        callee_summary = self._analyze_function(
                            callee,
                            code_objects[callee],
                            new_context,
                            code_objects,
                        )
                        if callee_summary.effect_summary and summary.effect_summary:
                            summary.effect_summary = summary.effect_summary.merge_with(
                                callee_summary.effect_summary
                            )
        return summary


class CrossFunctionAnalyzer:
    """
    High-level interface for cross-function analysis.
    """

    def __init__(self) -> None:
        self.call_graph_builder = CallGraphBuilder()
        self.effect_analyzer = EffectAnalyzer()
        self.escape_analyzer = EscapeAnalyzer()
        self.context_analyzer = ContextSensitiveAnalyzer()

    def analyze_module(self, module_code: Any) -> dict[str, Any]:
        """Analyze a module and return cross-function results."""
        results: dict[str, Any] = {}
        call_graph = self.call_graph_builder.build_from_module(module_code)
        results["call_graph"] = call_graph
        code_objects: dict[str, Any] = {"<module>": module_code}
        self._collect_code_objects(module_code, code_objects)
        effect_summaries = self.effect_analyzer.analyze_with_call_graph(call_graph, code_objects)
        results["effects"] = effect_summaries
        escape_results: dict[str, dict[int, EscapeInfo]] = {}
        for name, code in code_objects.items():
            escape_results[name] = self.escape_analyzer.analyze_function(code)
        results["escape"] = escape_results
        cs_summaries = self.context_analyzer.analyze(call_graph, code_objects)
        results["context_sensitive"] = cs_summaries
        return results

    def _collect_code_objects(
        self,
        code: Any,
        code_objects: dict[str, Any],
        prefix: str = "",
    ) -> None:
        """Collect all code objects from a module."""
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                name = const.co_name
                qualified = f"{prefix}.{name}" if prefix else name
                code_objects[name] = const
                self._collect_code_objects(const, code_objects, qualified)
