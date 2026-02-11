"""
Dead Code Detection for PySpectre.
This module identifies unreachable and unused code including:
- Unreachable statements after return/raise/break/continue
- Unused variables (assigned but never read)
- Unused functions (defined but never called)
- Unused imports
- Unreachable branches (conditions always true/false)
- Dead exception handlers
"""

from __future__ import annotations
import ast
import dis
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto
from typing import (
    Any,
)
from .cross_function import CallGraph, CallGraphBuilder
from .flow_sensitive import (
    CFGBuilder,
    LiveVariables,
)


class DeadCodeKind(Enum):
    """Types of dead code."""

    UNREACHABLE_CODE = auto()
    UNREACHABLE_BRANCH = auto()
    UNUSED_VARIABLE = auto()
    UNUSED_FUNCTION = auto()
    UNUSED_IMPORT = auto()
    UNUSED_PARAMETER = auto()
    REDUNDANT_ASSIGNMENT = auto()
    DEAD_STORE = auto()
    UNREACHABLE_HANDLER = auto()
    REDUNDANT_CONDITION = auto()


@dataclass
class DeadCode:
    """Represents a piece of dead code."""

    kind: DeadCodeKind
    file: str
    line: int
    end_line: int | None = None
    name: str = ""
    message: str = ""
    confidence: float = 1.0
    pc: int | None = None

    def format(self) -> str:
        """Format for display."""
        location = f"{self.file}:{self.line}"
        if self.end_line and self.end_line != self.line:
            location += f"-{self.end_line}"
        return f"[{self.kind.name}] {location}: {self.message}"


class UnreachableCodeDetector:
    """
    Detects unreachable code after control flow terminators.
    """

    def detect(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect unreachable code in function."""
        dead_code: list[DeadCode] = []
        instructions = list(dis.get_instructions(code))
        if not instructions:
            return dead_code
        jump_targets: set[int] = set()
        for instr in instructions:
            if instr.is_jump_target:
                jump_targets.add(instr.offset)
        unreachable = False
        unreachable_start: int | None = None
        current_line = code.co_firstlineno
        for i, instr in enumerate(instructions):
            is_start = instr.starts_line
            if is_start:
                if type(is_start) is int:
                    current_line = is_start
                elif hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                    current_line = instr.positions.lineno
            if instr.offset in jump_targets:
                if unreachable and unreachable_start:
                    dead_code.append(
                        DeadCode(
                            kind=DeadCodeKind.UNREACHABLE_CODE,
                            file=file_path,
                            line=unreachable_start,
                            end_line=current_line - 1,
                            message="Unreachable code after return/raise",
                        )
                    )
                unreachable = False
                unreachable_start = None
            if unreachable:
                continue
            if instr.opname in {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"}:
                if i + 1 < len(instructions):
                    next_instr = instructions[i + 1]
                    if next_instr.offset not in jump_targets:
                        unreachable = True
                        is_next_start = next_instr.starts_line
                        if is_next_start:
                            if isinstance(is_next_start, int):
                                unreachable_start = is_next_start
                            elif (
                                hasattr(next_instr, "positions")
                                and next_instr.positions
                                and next_instr.positions.lineno
                            ):
                                unreachable_start = next_instr.positions.lineno
                            else:
                                unreachable_start = current_line
                        else:
                            unreachable_start = current_line
        if unreachable and unreachable_start:
            dead_code.append(
                DeadCode(
                    kind=DeadCodeKind.UNREACHABLE_CODE,
                    file=file_path,
                    line=unreachable_start,
                    message="Unreachable code at end of function",
                )
            )
        return dead_code


class UnusedVariableDetector:
    """
    Detects variables that are assigned but never used.
    """

    IGNORED_NAMES: set[str] = {
        "_",
        "__",
        "___",
    }

    def detect(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect unused variables."""
        dead_code: list[DeadCode] = []
        assignments: dict[str, list[tuple[int, int]]] = defaultdict(list)
        uses: set[str] = set()
        instructions = list(dis.get_instructions(code))
        current_line = code.co_firstlineno
        for instr in instructions:
            is_start = instr.starts_line
            if is_start:
                if type(is_start) is int:
                    current_line = is_start
                elif hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                    current_line = instr.positions.lineno
            opname = instr.opname
            arg = instr.argval
            if opname in {"STORE_FAST", "STORE_NAME", "STORE_DEREF"}:
                name = str(arg)
                if name not in self.IGNORED_NAMES:
                    assignments[name].append((current_line, instr.offset))
            elif opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_DEREF", "LOAD_GLOBAL"}:
                uses.add(str(arg))
            elif opname in {"DELETE_FAST", "DELETE_NAME"}:
                uses.add(str(arg))
        for name, assign_locs in assignments.items():
            if name not in uses:
                if name in code.co_varnames[: code.co_argcount]:
                    continue
                if name.startswith("__") and name.endswith("__"):
                    continue
                for line, pc in assign_locs:
                    dead_code.append(
                        DeadCode(
                            kind=DeadCodeKind.UNUSED_VARIABLE,
                            file=file_path,
                            line=line,
                            name=name,
                            pc=pc,
                            message=f"Variable '{name}' is assigned but never used",
                        )
                    )
        return dead_code


class DeadStoreDetector:
    """
    Detects stores that are immediately overwritten without being read.
    """

    def detect(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect dead stores."""
        dead_code: list[DeadCode] = []
        builder = CFGBuilder()
        cfg = builder.build(code)
        live_analysis = LiveVariables(cfg)
        live_analysis.analyze()
        instructions = list(dis.get_instructions(code))
        current_line = code.co_firstlineno
        last_store: dict[str, tuple[int, int]] = {}
        for instr in instructions:
            is_start = instr.starts_line
            if is_start:
                if type(is_start) is int:
                    current_line = is_start
                elif hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                    current_line = instr.positions.lineno
            opname = instr.opname
            arg = instr.argval
            if opname in {"STORE_FAST", "STORE_NAME"}:
                name = str(arg)
                if name in last_store:
                    prev_line, prev_pc = last_store[name]
                    dead_code.append(
                        DeadCode(
                            kind=DeadCodeKind.DEAD_STORE,
                            file=file_path,
                            line=prev_line,
                            name=name,
                            pc=prev_pc,
                            message=f"Value of '{name}' is overwritten without being read",
                            confidence=0.8,
                        )
                    )
                last_store[name] = (current_line, instr.offset)
            elif opname in {"LOAD_FAST", "LOAD_NAME"}:
                name = str(arg)
                if name in last_store:
                    del last_store[name]
        return dead_code


class UnusedFunctionDetector:
    """
    Detects functions that are defined but never called.
    """

    EXEMPT_PATTERNS: set[str] = {
        "__init__",
        "__new__",
        "__del__",
        "__enter__",
        "__exit__",
        "__iter__",
        "__next__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__call__",
        "__len__",
        "__bool__",
        "__str__",
        "__repr__",
        "__hash__",
        "__eq__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__ne__",
        "__add__",
        "__sub__",
        "__mul__",
        "__div__",
        "main",
        "setup",
        "teardown",
        "setUp",
        "tearDown",
        "setUpClass",
        "tearDownClass",
    }

    def detect(
        self,
        call_graph: CallGraph,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect unused functions from call graph."""
        dead_code: list[DeadCode] = []
        for name, node in call_graph.nodes.items():
            if name in self.EXEMPT_PATTERNS:
                continue
            if name.startswith("test_"):
                continue
            if name.startswith("_") and not name.startswith("__"):
                continue
            if not node.callers and not node.is_entry_point:
                dead_code.append(
                    DeadCode(
                        kind=DeadCodeKind.UNUSED_FUNCTION,
                        file=file_path,
                        line=0,
                        name=name,
                        message=f"Function '{name}' is defined but never called",
                        confidence=0.7,
                    )
                )
        return dead_code


class UnusedParameterDetector:
    """
    Detects function parameters that are never used.
    """

    IGNORED_NAMES: set[str] = {"self", "cls", "_", "*args", "**kwargs"}

    def detect(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect unused parameters."""
        dead_code: list[DeadCode] = []
        params = set(code.co_varnames[: code.co_argcount])
        used: set[str] = set()
        for instr in dis.get_instructions(code):
            if instr.opname in {"LOAD_FAST", "LOAD_DEREF"}:
                used.add(str(instr.argval))
        for param in params:
            if param in self.IGNORED_NAMES:
                continue
            if param.startswith("_"):
                continue
            if param not in used:
                dead_code.append(
                    DeadCode(
                        kind=DeadCodeKind.UNUSED_PARAMETER,
                        file=file_path,
                        line=code.co_firstlineno,
                        name=param,
                        message=f"Parameter '{param}' is never used",
                        confidence=0.9,
                    )
                )
        return dead_code


class UnusedImportDetector:
    """
    Detects imports that are never used.
    This requires source code analysis, not just bytecode.
    """

    def detect_from_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect unused imports from source code."""
        dead_code: list[DeadCode] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return dead_code
        imports: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imports[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    name = alias.asname or alias.name
                    imports[name] = node.lineno
        used: set[str] = set()

        class NameCollector(ast.NodeVisitor):
            def visit_Name(self, node: ast.Name) -> None:
                used.add(node.id)
                self.generic_visit(node)

            def visit_Attribute(self, node: ast.Attribute) -> None:
                if isinstance(node.value, ast.Name):
                    used.add(node.value.id)
                self.generic_visit(node)

        collector = NameCollector()
        collector.visit(tree)
        for name, line in imports.items():
            base_name = name.split(".")[0]
            if base_name not in used and name not in used:
                dead_code.append(
                    DeadCode(
                        kind=DeadCodeKind.UNUSED_IMPORT,
                        file=file_path,
                        line=line,
                        name=name,
                        message=f"Import '{name}' is never used",
                        confidence=0.95,
                    )
                )
        return dead_code


class RedundantConditionDetector:
    """
    Detects conditions that always evaluate to the same value.
    """

    def detect(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect redundant conditions."""
        dead_code: list[DeadCode] = []
        instructions = list(dis.get_instructions(code))
        current_line = code.co_firstlineno
        stack: list[bool | None] = []
        for instr in instructions:
            is_start = instr.starts_line
            if is_start:
                if isinstance(is_start, int):
                    current_line = is_start
                elif hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                    current_line = instr.positions.lineno
            opname = instr.opname
            arg = instr.argval
            if opname == "LOAD_CONST":
                if isinstance(arg, bool):
                    stack.append(arg)
                elif arg is None:
                    stack.append(False)
                elif isinstance(arg, (int, float)) and arg == 0:
                    stack.append(False)
                elif isinstance(arg, str) and arg == "":
                    stack.append(False)
                else:
                    stack.append(None)
            elif opname in {
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_FORWARD_IF_TRUE",
                "POP_JUMP_FORWARD_IF_FALSE",
            }:
                if stack:
                    cond = stack.pop()
                    if cond is not None:
                        dead_code.append(
                            DeadCode(
                                kind=DeadCodeKind.REDUNDANT_CONDITION,
                                file=file_path,
                                line=current_line,
                                message=f"Condition is always {cond}",
                                confidence=0.95,
                            )
                        )
            elif opname.startswith("LOAD_"):
                stack.append(None)
            elif opname.startswith("STORE_") or opname == "POP_TOP":
                if stack:
                    stack.pop()
            elif opname.startswith("BINARY_") or opname == "COMPARE_OP":
                if len(stack) >= 2:
                    stack.pop()
                    stack.pop()
                stack.append(None)
        return dead_code


class DeadCodeAnalyzer:
    """
    High-level interface for dead code detection.
    """

    def __init__(self) -> None:
        self.unreachable_detector = UnreachableCodeDetector()
        self.unused_var_detector = UnusedVariableDetector()
        self.dead_store_detector = DeadStoreDetector()
        self.unused_func_detector = UnusedFunctionDetector()
        self.unused_param_detector = UnusedParameterDetector()
        self.unused_import_detector = UnusedImportDetector()
        self.redundant_cond_detector = RedundantConditionDetector()

    def analyze_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Analyze a function for dead code."""
        results: list[DeadCode] = []
        results.extend(self.unreachable_detector.detect(code, file_path))
        results.extend(self.unused_var_detector.detect(code, file_path))
        results.extend(self.dead_store_detector.detect(code, file_path))
        results.extend(self.unused_param_detector.detect(code, file_path))
        results.extend(self.redundant_cond_detector.detect(code, file_path))
        return results

    def analyze_module(
        self,
        module_code: Any,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Analyze a module for dead code."""
        results: list[DeadCode] = []
        results.extend(self.unused_import_detector.detect_from_source(source, file_path))
        results.extend(self.analyze_function(module_code, file_path))
        builder = CallGraphBuilder()
        call_graph = builder.build_from_module(module_code)
        results.extend(self.unused_func_detector.detect(call_graph, file_path))
        self._analyze_nested_functions(module_code, file_path, results)
        return results

    def _analyze_nested_functions(
        self,
        code: Any,
        file_path: str,
        results: list[DeadCode],
    ) -> None:
        """Recursively analyze nested functions."""
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                results.extend(self.analyze_function(const, file_path))
                self._analyze_nested_functions(const, file_path, results)

    def analyze_file(self, file_path: str) -> list[DeadCode]:
        """Analyze a file for dead code."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            code = compile(source, file_path, "exec")
            return self.analyze_module(code, source, file_path)
        except SyntaxError as e:
            return [
                DeadCode(
                    kind=DeadCodeKind.UNREACHABLE_CODE,
                    file=file_path,
                    line=e.lineno or 0,
                    message=f"Syntax error prevents analysis: {e.msg}",
                )
            ]
        except Exception:
            return []
