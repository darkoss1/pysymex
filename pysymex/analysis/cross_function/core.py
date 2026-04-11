# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Cross-function analysis â€” core logic classes and helpers."""

from __future__ import annotations

from collections import defaultdict
from types import CodeType
from typing import (
    cast,
)

import z3

from pysymex._compat import get_starts_line
from pysymex.analysis.specialized.escape import EscapeAnalyzer, EscapeInfo
from pysymex.core.solver.constraints import structural_hash_sorted
from pysymex.core.solver.independence import ConstraintIndependenceOptimizer
from pysymex.core.cache import get_instructions as _cached_get_instructions
from pysymex.core.types.scalars import SymbolicValue

from ..type_inference import PyType, TypeKind
from .types import (
    CallContext,
    CallGraphNode,
    CallSiteInfo,
    ContextSensitiveSummary,
    Effect,
    EffectSummary,
)

__all__ = [
    "CallGraph",
    "CallGraphBuilder",
    "ContextSensitiveAnalyzer",
    "CrossFunctionAnalyzer",
    "EffectAnalyzer",
    "FunctionSummaryCache",
]


class FunctionSummaryCache:
    """
    Cache for function summaries supporting canonicalized constraint hashing.
    Enables reuse of summaries across different symbolic variables if constraints match structurally.
    """

    def __init__(self) -> None:
        self._cache: dict[tuple[str, tuple[str, ...], int], object] = {}
        self._hits = 0
        self._misses = 0

    def get(
        self, func_name: str, args: list[object], path_constraints: list[z3.BoolRef]
    ) -> object | None:
        """Get a summary for a function call with specific arguments and constraints."""
        key = self._compute_key(func_name, args, path_constraints)
        if key in self._cache:
            self._hits += 1
            return self._cache[key]
        self._misses += 1
        return None

    def put(
        self,
        func_name: str,
        args: list[object],
        path_constraints: list[z3.BoolRef],
        summary: object,
    ) -> None:
        """Cache a summary for a function call."""
        key = self._compute_key(func_name, args, path_constraints)
        self._cache[key] = summary

    def _compute_key(
        self, func_name: str, args: list[object], path_constraints: list[z3.BoolRef]
    ) -> tuple[str, tuple[str, ...], int]:
        """Compute canonical hash key for arguments and their constraints."""

        canonical_map: list[tuple[z3.ExprRef, z3.ExprRef]] = []
        target_vars: set[z3.ExprRef] = set()

        sym_args: list[str] = []

        for i, arg in enumerate(args):
            arg_type = type(arg).__name__
            if isinstance(arg, SymbolicValue):
                target_vars.add(arg.z3_int)
                canonical_map.append((arg.z3_int, z3.Int(f"arg_{i}_int")))
                target_vars.add(arg.z3_bool)
                canonical_map.append((arg.z3_bool, z3.Bool(f"arg_{i}_bool")))
                sym_args.append(str(arg_type))
            else:
                sym_args.append(f"{arg_type}:{arg!s}")

        if not path_constraints:
            constraint_hash = 0
        else:
            optimizer = ConstraintIndependenceOptimizer()
            for c in path_constraints:
                optimizer.register_constraint(c)

            if target_vars:
                dummy_query = z3.And(*[(v == v) for v in target_vars])
                relevant_slice = optimizer.slice_for_query(path_constraints, dummy_query)
            else:
                relevant_slice = []

            canonical_constraints: list[z3.BoolRef] = []
            for c in relevant_slice:
                if canonical_map:
                    canonical_constraints.append(
                        cast("z3.BoolRef", z3.substitute(c, *canonical_map))
                    )
                else:
                    canonical_constraints.append(c)

            constraint_hash = structural_hash_sorted(canonical_constraints)

        args_tuple: tuple[str, ...] = tuple(sym_args)
        return (func_name, args_tuple, constraint_hash)


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
        **kwargs: object,
    ) -> None:
        """Add a call edge to the graph."""
        caller_node = self.add_function(caller)
        callee_node = self.add_function(callee)

        raw_arg_count = kwargs.get("arg_count", 0)
        arg_count = int(raw_arg_count) if isinstance(raw_arg_count, (int, float, str)) else 0
        call_site = CallSiteInfo(
            caller=caller,
            callee=callee,
            line=line,
            pc=pc,
            arg_count=arg_count,
            has_kwargs=bool(kwargs.get("has_kwargs", False)),
            has_varargs=bool(kwargs.get("has_varargs", False)),
            is_method_call=bool(kwargs.get("is_method_call", False)),
            is_static=bool(kwargs.get("is_static", False)),
            is_super_call=bool(kwargs.get("is_super_call", False)),
            is_dynamic=bool(kwargs.get("is_dynamic", False)),
            possible_callees=cast("set[str]", kwargs.get("possible_callees", set())),
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
        result: list[str] = []
        while queue:
            func = queue.pop(0)
            result.append(func)
            for callee in self.get_callees(func):
                if callee in in_degree:
                    in_degree[callee] -= 1
                    if in_degree[callee] == 0:
                        queue.append(callee)
        for name in self.nodes:
            if name not in result:
                result.append(name)
        result.reverse()
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

    def build_from_module(self, module_code: CodeType) -> CallGraph:
        """Build call graph from a module's code object."""
        self.call_graph = CallGraph()
        self._process_code(module_code, "<module>")
        self._find_functions(module_code)
        if "<module>" in self.call_graph.nodes:
            self.call_graph.nodes["<module>"].is_entry_point = True
            self.call_graph.entry_points.add("<module>")
        self.call_graph.find_recursive()
        return self.call_graph

    def _find_functions(self, code: CodeType, prefix: str = "") -> None:
        """Find all functions in a code object."""
        for const in code.co_consts:
            if isinstance(const, CodeType):
                func_name = const.co_name
                qualified_name = f"{prefix}.{func_name}" if prefix else func_name
                self.call_graph.add_function(func_name, qualified_name)
                self._process_code(const, func_name)
                self._find_functions(const, qualified_name)

    def _process_code(self, code: CodeType, func_name: str) -> None:
        """Process a code object for call sites."""
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        stack_items: list[str] = []
        for _i, instr in enumerate(instructions):
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
                stack_items.append(str(arg))
            elif opname == "LOAD_CONST":
                stack_items.append(f"const:{arg}")
            elif opname == "LOAD_ATTR" or opname == "LOAD_METHOD":
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

    def analyze_function(self, code: CodeType, name: str = "") -> EffectSummary:
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
        for instr in _cached_get_instructions(code):
            opname = instr.opname
            arg = instr.argval
            if opname == "LOAD_GLOBAL":
                effects |= Effect.READ_GLOBAL
                reads_globals.add(str(arg))
            elif opname == "STORE_GLOBAL" or opname == "DELETE_GLOBAL":
                effects |= Effect.WRITE_GLOBAL
                writes_globals.add(str(arg))
            elif opname == "LOAD_ATTR":
                effects |= Effect.READ_HEAP
                reads_attributes.add(str(arg))
            elif opname == "STORE_ATTR" or opname == "DELETE_ATTR":
                effects |= Effect.WRITE_HEAP
                writes_attributes.add(str(arg))
            elif opname == "BINARY_SUBSCR":
                effects |= Effect.READ_HEAP
            elif opname == "STORE_SUBSCR" or opname == "DELETE_SUBSCR":
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
        code_objects: dict[str, CodeType],
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
        base_name = func_name.rsplit(".", maxsplit=1)[-1]
        if base_name in self.PURE_FUNCTIONS:
            return EffectSummary(effects=Effect.NONE)
        if base_name in self.IO_FUNCTIONS:
            return EffectSummary(effects=Effect.IO | Effect.RAISE)
        return EffectSummary(effects=Effect.IMPURE)


_PYTHON_TYPE_TO_PYTYPE: dict[type, PyType] = {
    int: PyType.int_(),
    float: PyType.float_(),
    str: PyType.str_(),
    bool: PyType.bool_(),
    bytes: PyType(kind=TypeKind.BYTES, name="bytes"),
    type(None): PyType.none(),
}

PYTHON_TYPE_TO_PYTYPE = _PYTHON_TYPE_TO_PYTYPE


def _infer_return_type(code: CodeType) -> PyType | None:
    """Infer the return type of a function from its bytecode.

    Walks RETURN_VALUE and RETURN_CONST opcodes, resolves the returned
    constant (or the constant loaded immediately before RETURN_VALUE),
    and computes the union of all return types.  Returns ``None`` if
    the return type cannot be determined or is too heterogeneous.
    """
    return_types: list[PyType] = []
    instructions = _cached_get_instructions(code)

    for i, instr in enumerate(instructions):
        opname = instr.opname
        if opname == "RETURN_CONST":
            _obj: object = instr.argval
            val_type = type(_obj)
            py_type = _PYTHON_TYPE_TO_PYTYPE.get(val_type)
            if py_type is not None:
                return_types.append(py_type)
        elif opname == "RETURN_VALUE":
            if i > 0:
                prev = instructions[i - 1]
                if prev.opname == "LOAD_CONST":
                    _obj2: object = prev.argval
                    val_type = type(_obj2)
                    py_type = _PYTHON_TYPE_TO_PYTYPE.get(val_type)
                    if py_type is not None:
                        return_types.append(py_type)
                elif prev.opname in {
                    "LOAD_FAST",
                    "LOAD_GLOBAL",
                    "LOAD_DEREF",
                    "LOAD_NAME",
                } or prev.opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
                    pass

    if not return_types:
        return PyType.none()

    unique = list(dict.fromkeys(return_types))
    if len(unique) == 1:
        return unique[0]

    non_none = [t for t in unique if t.kind != TypeKind.NONE]
    has_none = any(t.kind == TypeKind.NONE for t in unique)
    if len(non_none) == 1 and has_none:
        result = PyType(
            kind=non_none[0].kind,
            name=f"Optional[{non_none[0].name}]",
            nullable=True,
        )
        return result

    return None


infer_return_type = _infer_return_type


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
        code_objects: dict[str, CodeType],
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
        code: CodeType,
        context: CallContext,
        code_objects: dict[str, CodeType],
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
        summary.return_type = _infer_return_type(code)
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
        self.function_summary_cache = FunctionSummaryCache()

    def analyze_module(self, module_code: CodeType) -> dict[str, object]:
        """Analyze a module and return cross-function results."""
        results: dict[str, object] = {}
        call_graph = self.call_graph_builder.build_from_module(module_code)
        results["call_graph"] = call_graph
        code_objects: dict[str, CodeType] = {"<module>": module_code}
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
        code: CodeType,
        code_objects: dict[str, CodeType],
        prefix: str = "",
    ) -> None:
        """Collect all code objects from a module."""
        for const in code.co_consts:
            if isinstance(const, CodeType):
                name = const.co_name
                qualified = f"{prefix}.{name}" if prefix else name
                code_objects[qualified] = const
                if name not in code_objects:
                    code_objects[name] = const
                self._collect_code_objects(const, code_objects, qualified)

