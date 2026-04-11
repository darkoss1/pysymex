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

"""Dead code detector implementations.

Provides all concrete detector classes used by DeadCodeAnalyzer:
- UnreachableCodeDetector
- UnusedVariableDetector
- DeadStoreDetector
- UnusedFunctionDetector
- UnusedParameterDetector
- UnusedImportDetector
- RedundantConditionDetector
"""

from __future__ import annotations

import ast
import dis
import inspect
from collections import defaultdict
from collections.abc import Sequence
from types import CodeType
from typing import cast

from pysymex.core.cache import get_instructions as _cached_get_instructions

from ..cross_function import CallGraph
from ..control.cfg import CFGBuilder
from ..dataflow.core import LiveVariables
from .types import DeadCode, DeadCodeKind


class UnreachableCodeDetector:
    """Detects unreachable code after control-flow terminators.

    Scans bytecode for instructions following ``RETURN_VALUE``,
    ``RETURN_CONST``, or ``RAISE_VARARGS`` that are not jump targets.
    """

    _GENERATOR_FLAG = inspect.CO_GENERATOR
    _ASYNC_GENERATOR_FLAG = inspect.CO_ASYNC_GENERATOR
    _COROUTINE_FLAG = inspect.CO_COROUTINE

    def detect(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect unreachable code in function."""
        dead_code: list[DeadCode] = []
        instructions = _cached_get_instructions(code)
        if not instructions:
            return dead_code

        is_generator = bool(code.co_flags & self._GENERATOR_FLAG)
        is_async = bool(code.co_flags & self._COROUTINE_FLAG)
        is_async_gen = bool(code.co_flags & self._ASYNC_GENERATOR_FLAG)
        is_genexpr = (
            code.co_qualname.endswith(".<genexpr>")
            if hasattr(code, "co_qualname")
            else code.co_name == "<genexpr>"
        )

        jump_targets: set[int] = set()
        for instr in instructions:
            if instr.is_jump_target:
                jump_targets.add(instr.offset)
        unreachable = False
        unreachable_start: int | None = None
        unreachable_start_idx: int | None = None
        terminator_line: int | None = None
        current_line = code.co_firstlineno
        for i, instr in enumerate(instructions):
            is_start = instr.starts_line
            if is_start:
                if type(is_start) is int:
                    current_line = is_start
                elif hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                    current_line = instr.positions.lineno
            if instr.offset in jump_targets or instr.opname == "PUSH_EXC_INFO":
                if unreachable and unreachable_start:
                    if instr.opname != "PUSH_EXC_INFO":
                        has_user_code = self._region_has_user_code(
                            instructions,
                            unreachable_start_idx,
                            i,
                            terminator_line,
                        )
                        if has_user_code:
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
                unreachable_start_idx = None
            if unreachable:
                continue
            if instr.opname in {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"}:
                if i + 1 < len(instructions):
                    next_instr = instructions[i + 1]
                    if next_instr.offset not in jump_targets:
                        unreachable = True
                        unreachable_start_idx = i + 1
                        terminator_line = current_line
                        is_next_start = next_instr.starts_line
                        if is_next_start:
                            if type(is_next_start) is int:
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
            if (
                is_genexpr
                or is_generator
                or is_async
                or is_async_gen
                or self._is_only_implicit_return(
                    instructions, unreachable_start_idx, len(instructions)
                )
            ):
                pass
            else:
                has_user_code = self._region_has_user_code(
                    instructions,
                    unreachable_start_idx,
                    len(instructions),
                    terminator_line,
                )
                if has_user_code:
                    dead_code.append(
                        DeadCode(
                            kind=DeadCodeKind.UNREACHABLE_CODE,
                            file=file_path,
                            line=unreachable_start,
                            message="Unreachable code at end of function",
                        )
                    )
        return dead_code

    @staticmethod
    def _region_has_user_code(
        instructions: Sequence[dis.Instruction],
        start_idx: int | None,
        end_idx: int,
        terminator_line: int | None,
    ) -> bool:
        """Check if an unreachable bytecode region contains real user code.

        Returns True only if the region has an instruction that starts a
        source line strictly *after* the terminator line.  CPython exception
        cleanup opcodes reference the try/except source lines (at or before
        the terminator), so this distinguishes real dead code from
        compiler-generated artifacts.
        """
        if start_idx is None:
            return False
        for j in range(start_idx, end_idx):
            instr_j = instructions[j]
            sl = instr_j.starts_line
            line_val: int | None = None
            if sl:
                if type(sl) is int:
                    line_val = sl
                elif (
                    hasattr(instr_j, "positions") and instr_j.positions and instr_j.positions.lineno
                ):
                    line_val = instr_j.positions.lineno
            if line_val is not None and (terminator_line is None or line_val > terminator_line):
                return True
        return False

    @staticmethod
    def _is_only_implicit_return(
        instructions: Sequence[dis.Instruction],
        start_idx: int | None,
        end_idx: int,
    ) -> bool:
        """Check if an unreachable region contains only implicit return bytecode.

        CPython always appends a RETURN_VALUE/RETURN_CONST None at the end of
        every code object.  When the last real statement is a return/raise, this
        implicit return appears unreachable but is not user code.
        """
        if start_idx is None:
            return False
        if start_idx >= end_idx:
            return False
        for i in range(start_idx, end_idx):
            opname = instructions[i].opname
            if opname not in (
                "RETURN_VALUE",
                "RETURN_CONST",
                "LOAD_CONST",
                "NOP",
                "RESUME",
                "POP_TOP",
                "PUSH_NULL",
            ):
                return False
        return True


class UnusedVariableDetector:
    """Detects variables assigned but never read.

    Compares ``STORE_*`` assignments against ``LOAD_*`` uses,
    including uses in nested code objects.
    """

    IGNORED_NAMES: set[str] = {
        "_",
        "__",
        "___",
    }

    def detect(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect unused variables."""
        dead_code: list[DeadCode] = []
        assignments: dict[str, list[tuple[int, int]]] = defaultdict(list)
        uses: set[str] = set()
        instructions = _cached_get_instructions(code)
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
            elif opname in {
                "LOAD_FAST",
                "LOAD_NAME",
                "LOAD_DEREF",
                "LOAD_GLOBAL",
                "LOAD_FAST_AND_CLEAR",
            } or opname in {"DELETE_FAST", "DELETE_NAME"}:
                uses.add(str(arg))

            elif opname == "STORE_FAST_LOAD_FAST":
                if isinstance(arg, tuple):
                    _arg = cast("tuple[object, ...]", arg)
                    sname, lname = _arg
                    if str(sname) not in self.IGNORED_NAMES:
                        assignments[str(sname)].append((current_line, instr.offset))
                    uses.add(str(lname))
            elif opname == "STORE_FAST_STORE_FAST":
                if isinstance(arg, tuple):
                    for n in cast("tuple[object, ...]", arg):
                        if str(n) not in self.IGNORED_NAMES:
                            assignments[str(n)].append((current_line, instr.offset))
            elif opname == "LOAD_FAST_LOAD_FAST":
                if isinstance(arg, tuple):
                    for n in cast("tuple[object, ...]", arg):
                        uses.add(str(n))

        nested_uses = self._collect_nested_uses(code)

        for name, assign_locs in assignments.items():
            if name not in uses and name not in nested_uses:
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

    @staticmethod
    def _collect_nested_uses(code: CodeType) -> set[str]:
        """Collect all variable names referenced in nested code objects."""
        uses: set[str] = set()
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                for instr in _cached_get_instructions(const):
                    if instr.opname in {
                        "LOAD_FAST",
                        "LOAD_NAME",
                        "LOAD_DEREF",
                        "LOAD_GLOBAL",
                        "LOAD_CLASSDEREF",
                        "LOAD_FAST_AND_CLEAR",
                    }:
                        uses.add(str(instr.argval))
                    elif instr.opname in {
                        "LOAD_FAST_LOAD_FAST",
                        "STORE_FAST_LOAD_FAST",
                    }:
                        if isinstance(instr.argval, tuple):
                            for n in cast("tuple[object, ...]", instr.argval):
                                uses.add(str(n))

                uses.update(UnusedVariableDetector._collect_nested_uses(const))

        for const in code.co_consts:
            if hasattr(const, "co_code"):
                uses.update(const.co_freevars)
        return uses

    @staticmethod
    def collect_nested_uses(code: CodeType) -> set[str]:
        """Public wrapper for nested-use collection."""
        return UnusedVariableDetector._collect_nested_uses(code)


class DeadStoreDetector:
    """
    Detects stores that are immediately overwritten without being read.
    """

    def detect(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect dead stores.

        Note: Currently only tracks STORE_FAST/STORE_NAME. STORE_ATTR
        (e.g. ``self.x = val``) is intentionally not tracked because
        cross-method attribute usage tracking is not yet wired in.
        See ``_collect_class_attrs_used()`` for the collected-but-unused data.
        """
        dead_code: list[DeadCode] = []
        builder = CFGBuilder()
        cfg = builder.build(code)
        live_analysis = LiveVariables(cfg)
        live_analysis.analyze()
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno

        jump_targets: set[int] = set()
        for instr in instructions:
            if instr.is_jump_target:
                jump_targets.add(instr.offset)

        loop_vars: set[str] = set()
        for i, instr in enumerate(instructions):
            if instr.opname in {"FOR_ITER", "GET_ITER"}:
                for j in range(i + 1, min(i + 4, len(instructions))):
                    if instructions[j].opname in {"STORE_FAST", "STORE_NAME"}:
                        loop_vars.add(str(instructions[j].argval))
                        break

                    if instructions[j].opname == "STORE_FAST_LOAD_FAST":
                        if isinstance(instructions[j].argval, tuple):
                            loop_vars.add(str(instructions[j].argval[0]))
                        break
                    if instructions[j].opname == "STORE_FAST_STORE_FAST":
                        if isinstance(instructions[j].argval, tuple):
                            for n in instructions[j].argval:
                                loop_vars.add(str(n))
                        break
                    if instructions[j].opname == "UNPACK_SEQUENCE":
                        unpack_count = instructions[j].argval
                        if not isinstance(unpack_count, int):
                            break
                        for k in range(j + 1, min(j + 1 + unpack_count, len(instructions))):
                            if instructions[k].opname in {"STORE_FAST", "STORE_NAME"}:
                                loop_vars.add(str(instructions[k].argval))
                            elif instructions[k].opname == "STORE_FAST_STORE_FAST":
                                if isinstance(instructions[k].argval, tuple):
                                    for n in instructions[k].argval:
                                        loop_vars.add(str(n))
                        break

        last_store: dict[str, tuple[int, int]] = {}
        for instr in instructions:
            is_start = instr.starts_line
            if is_start:
                if type(is_start) is int:
                    current_line = is_start
                elif hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                    current_line = instr.positions.lineno

            if instr.offset in jump_targets:
                last_store.clear()

            opname = instr.opname
            arg = instr.argval

            if opname in {"STORE_FAST", "STORE_NAME"}:
                name = str(arg)

                if name in loop_vars:
                    last_store.pop(name, None)
                    continue
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
            elif opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_FAST_AND_CLEAR"} or opname in {
                "DELETE_FAST",
                "DELETE_NAME",
            }:
                name = str(arg)
                last_store.pop(name, None)

            elif opname == "STORE_FAST_LOAD_FAST":
                if isinstance(arg, tuple) and len(arg) >= 2:
                    _arg = cast("tuple[object, ...]", arg)
                    sname, lname = str(_arg[0]), str(_arg[1])

                    last_store.pop(lname, None)
                    if sname in loop_vars:
                        last_store.pop(sname, None)
                    else:
                        last_store[sname] = (current_line, instr.offset)
            elif opname == "STORE_FAST_STORE_FAST":
                if isinstance(arg, tuple):
                    for n in cast("tuple[object, ...]", arg):
                        name = str(n)
                        if name in loop_vars:
                            last_store.pop(name, None)
                        else:
                            last_store[name] = (current_line, instr.offset)
            elif opname == "LOAD_FAST_LOAD_FAST":
                if isinstance(arg, tuple):
                    for n in cast("tuple[object, ...]", arg):
                        name = str(n)
                        last_store.pop(name, None)

            elif opname in {
                "JUMP_FORWARD",
                "JUMP_BACKWARD",
                "JUMP_ABSOLUTE",
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_FORWARD_IF_TRUE",
                "POP_JUMP_FORWARD_IF_FALSE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
                "POP_JUMP_FORWARD_IF_NONE",
                "POP_JUMP_FORWARD_IF_NOT_NONE",
                "RERAISE",
            }:
                last_store.clear()
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

    @staticmethod
    def _is_stub_body(code: CodeType) -> bool:
        """Check if a function body is a stub (only ``...``, ``pass``, or ``raise NotImplementedError``).

        Protocol methods and abstract stubs inherently don't use their
        parameters â€” flagging them as unused is a false positive.
        """
        for instr in _cached_get_instructions(code):
            if instr.opname in {
                "RESUME",
                "NOP",
                "POP_TOP",
                "RETURN_VALUE",
                "PUSH_NULL",
                "PRECALL",
            }:
                continue

            if instr.opname == "RETURN_CONST" and instr.argval is None:
                continue
            if instr.opname == "LOAD_CONST" and instr.argval in (None, Ellipsis):
                continue

            if (
                instr.opname in {"LOAD_GLOBAL", "LOAD_NAME"}
                and instr.argval == "NotImplementedError"
            ):
                continue
            if instr.opname in {"CALL", "CALL_FUNCTION"}:
                continue
            if instr.opname == "RAISE_VARARGS":
                continue
            return False
        return True

    def detect(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect unused parameters."""
        dead_code: list[DeadCode] = []

        if self._is_stub_body(code):
            return dead_code
        params = set(code.co_varnames[: code.co_argcount])
        used: set[str] = set()
        for instr in _cached_get_instructions(code):
            if instr.opname in {
                "LOAD_FAST",
                "LOAD_DEREF",
                "LOAD_NAME",
                "LOAD_GLOBAL",
                "LOAD_CLASSDEREF",
                "LOAD_FAST_AND_CLEAR",
            }:
                used.add(str(instr.argval))
            elif instr.opname in {"LOAD_FAST_LOAD_FAST", "STORE_FAST_LOAD_FAST"}:
                if isinstance(instr.argval, tuple):
                    for n in cast("tuple[object, ...]", instr.argval):
                        used.add(str(n))

        nested_uses = UnusedVariableDetector.collect_nested_uses(code)
        for param in params:
            if param in self.IGNORED_NAMES:
                continue
            if param.startswith("_"):
                continue
            if param not in used and param not in nested_uses:
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
            """Visitor for collecting variable names from an AST node."""

            def visit_Name(self, node: ast.Name) -> None:
                """Visit name."""
                used.add(node.id)
                self.generic_visit(node)

            def visit_Attribute(self, node: ast.Attribute) -> None:
                """Visit attribute."""
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
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[DeadCode]:
        """Detect redundant conditions."""
        dead_code: list[DeadCode] = []
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        stack: list[bool | None] = []
        for instr in instructions:
            is_start = instr.starts_line
            if is_start:
                if type(is_start) is int:
                    current_line = is_start
                elif hasattr(instr, "positions") and instr.positions and instr.positions.lineno:
                    current_line = instr.positions.lineno
            opname = instr.opname
            arg = instr.argval
            if opname == "LOAD_CONST":
                if isinstance(arg, bool):
                    stack.append(arg)
                elif (
                    arg is None
                    or (isinstance(arg, (int, float)) and arg == 0)
                    or (isinstance(arg, str) and arg == "")
                ):
                    stack.append(False)
                else:
                    stack.append(None)
            elif opname == "TO_BOOL":
                if stack:
                    stack[-1] = None
            elif opname in {
                "SEND",
                "GET_AWAITABLE",
                "YIELD_VALUE",
                "RESUME",
                "GET_ITER",
                "FOR_ITER",
                "END_SEND",
            }:
                stack.clear()
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

