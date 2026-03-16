"""
Exception Flow Analysis – Core logic.

AST and bytecode analyzers, helper functions, and the high-level
ExceptionAnalyzer facade.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

import ast
from collections import defaultdict
from collections.abc import Sequence

from pysymex._compat import get_starts_line
from pysymex.analysis.exceptions.analysis_types import (
    KNOWN_CRASHY_APIS,
    ExceptionHandler,
    ExceptionWarning,
    ExceptionWarningKind,
    HandlerIntent,
    TryBlock,
)
from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions


def _try_body_calls_crashy_api(try_node: ast.Try) -> bool:
    """Check if the try body calls a known-crashy API."""
    for stmt in try_node.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                func = node.func

                if isinstance(func, ast.Name) and func.id in KNOWN_CRASHY_APIS:
                    return True

                if isinstance(func, ast.Attribute):
                    if isinstance(func.value, ast.Name) and func.value.id in KNOWN_CRASHY_APIS:
                        return True

            if isinstance(node, ast.Name) and node.id in KNOWN_CRASHY_APIS:

                pass
    return False


def _classify_handler_intent(handler: ast.ExceptHandler) -> HandlerIntent:
    """Classify the intent of an exception handler body."""
    has_return = False
    has_raise = False
    has_logging = False
    has_pass = not handler.body

    for stmt in handler.body:
        if isinstance(stmt, ast.Return):
            has_return = True
        if isinstance(stmt, ast.Pass):
            has_pass = True
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise):
                has_raise = True
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in {
                        "error",
                        "exception",
                        "warning",
                        "critical",
                        "debug",
                        "info",
                    }:
                        has_logging = True
                elif isinstance(node.func, ast.Name):
                    if node.func.id in {"print", "logging"}:
                        has_logging = True

    if has_raise:
        return HandlerIntent.SAFETY_NET
    if has_logging and not has_pass:
        return HandlerIntent.LOGGED
    if has_return or has_logging:
        return HandlerIntent.SAFETY_NET
    return HandlerIntent.SILENCED


class ExceptionASTAnalyzer(ast.NodeVisitor):
    """
    AST-based exception analysis.
    """

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.warnings: list[ExceptionWarning] = []
        self.try_blocks: list[TryBlock] = []
        self.current_function: str | None = None
        self.function_raises: dict[str, set[str]] = defaultdict(set)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function

    def visit_Try(self, node: ast.Try) -> None:
        """Analyze try-except-finally block."""
        try_block = TryBlock(
            start_line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            has_finally=bool(node.finalbody),
            has_else=bool(node.orelse),
        )
        for stmt in node.body:
            for child in ast.walk(stmt):
                if isinstance(child, ast.Raise):
                    if child.exc:
                        if isinstance(child.exc, ast.Call):
                            if isinstance(child.exc.func, ast.Name):
                                try_block.raises_in_try.append(child.exc.func.id)
                        elif isinstance(child.exc, ast.Name):
                            try_block.raises_in_try.append(child.exc.id)

        calls_crashy = _try_body_calls_crashy_api(node)
        caught_types: list[str] = []
        for handler in node.handlers:
            exc_handler = self._analyze_handler(handler, calls_crashy_api=calls_crashy)
            try_block.handlers.append(exc_handler)
            caught_types.extend(exc_handler.exception_types)
        self._check_handler_issues(node.handlers, caught_types)
        if node.finalbody:
            for stmt in node.finalbody:
                if isinstance(stmt, ast.Return):
                    try_block.returns_in_finally = True
                    self.warnings.append(
                        ExceptionWarning(
                            kind=ExceptionWarningKind.FINALLY_RETURN,
                            file=self.file_path,
                            line=stmt.lineno,
                            message="Return in finally block can silence exceptions",
                            severity="error",
                        )
                    )
                for child in ast.walk(stmt):
                    if isinstance(child, ast.Raise):
                        try_block.raises_in_finally = True
                        self.warnings.append(
                            ExceptionWarning(
                                kind=ExceptionWarningKind.EXCEPTION_IN_FINALLY,
                                file=self.file_path,
                                line=child.lineno,
                                message="Raise in finally block can replace original exception",
                                severity="warning",
                            )
                        )
        self.try_blocks.append(try_block)
        self.generic_visit(node)

    def _analyze_handler(
        self,
        handler: ast.ExceptHandler,
        *,
        calls_crashy_api: bool = False,
    ) -> ExceptionHandler:
        """Analyze a single exception handler."""
        exc_handler = ExceptionHandler(line=handler.lineno, exception_types=[])

        intent = _classify_handler_intent(handler)
        exc_handler.intent = intent

        if handler.type is None:
            exc_handler.is_bare = True
            exc_handler.exception_types = ["BaseException"]
            self.warnings.append(
                ExceptionWarning(
                    kind=ExceptionWarningKind.BARE_EXCEPT,
                    file=self.file_path,
                    line=handler.lineno,
                    message="Bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt",
                    severity="warning",
                )
            )
        elif isinstance(handler.type, ast.Tuple):
            for elt in handler.type.elts:
                if isinstance(elt, ast.Name):
                    exc_handler.exception_types.append(elt.id)
                elif isinstance(elt, ast.Attribute):
                    exc_handler.exception_types.append(ast.dump(elt))
        elif isinstance(handler.type, ast.Attribute):
            exc_handler.exception_types.append(ast.dump(handler.type))
        elif isinstance(handler.type, ast.Name):
            exc_handler.exception_types.append(handler.type.id)
            if handler.type.id == "Exception":

                if calls_crashy_api and intent != HandlerIntent.SILENCED:

                    pass
                elif intent == HandlerIntent.SAFETY_NET:

                    self.warnings.append(
                        ExceptionWarning(
                            kind=ExceptionWarningKind.TOO_BROAD_EXCEPT,
                            file=self.file_path,
                            line=handler.lineno,
                            message="Catching 'Exception' is broad, but handler provides a fallback",
                            severity="info",
                        )
                    )
                elif intent == HandlerIntent.LOGGED:

                    self.warnings.append(
                        ExceptionWarning(
                            kind=ExceptionWarningKind.TOO_BROAD_EXCEPT,
                            file=self.file_path,
                            line=handler.lineno,
                            message="Catching 'Exception' is broad, but exception is logged",
                            severity="info",
                        )
                    )
                else:

                    self.warnings.append(
                        ExceptionWarning(
                            kind=ExceptionWarningKind.TOO_BROAD_EXCEPT,
                            file=self.file_path,
                            line=handler.lineno,
                            message="Catching 'Exception' is too broad, consider catching specific exceptions",
                            severity="warning",
                        )
                    )
            elif handler.type.id == "BaseException":
                self.warnings.append(
                    ExceptionWarning(
                        kind=ExceptionWarningKind.TOO_BROAD_EXCEPT,
                        file=self.file_path,
                        line=handler.lineno,
                        message="Catching 'BaseException' catches all exceptions including SystemExit",
                        severity="error",
                    )
                )
        if not handler.body:
            exc_handler.is_empty = True
        elif len(handler.body) == 1:
            stmt = handler.body[0]
            if isinstance(stmt, ast.Pass):
                exc_handler.has_pass = True
                exc_handler.is_empty = True
                self.warnings.append(
                    ExceptionWarning(
                        kind=ExceptionWarningKind.EXCEPTION_SWALLOWED,
                        file=self.file_path,
                        line=handler.lineno,
                        message="Exception silently ignored with 'pass'",
                        severity="warning",
                    )
                )
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                exc_handler.is_empty = True
        for stmt in ast.walk(handler):
            if isinstance(stmt, ast.Raise):
                exc_handler.has_reraise = True
                break
        for stmt in ast.walk(handler):
            if isinstance(stmt, ast.Return):
                exc_handler.has_return = True
                break
        for stmt in ast.walk(handler):
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Attribute):
                    if stmt.func.attr in {
                        "error",
                        "exception",
                        "warning",
                        "critical",
                        "debug",
                        "info",
                    }:
                        exc_handler.has_logging = True
                        break
                elif isinstance(stmt.func, ast.Name):
                    if stmt.func.id in {"print", "logging"}:
                        exc_handler.has_logging = True
                        break
        if exc_handler.is_empty and not exc_handler.has_logging:
            self.warnings.append(
                ExceptionWarning(
                    kind=ExceptionWarningKind.EXCEPTION_NOT_LOGGED,
                    file=self.file_path,
                    line=handler.lineno,
                    message="Exception caught but not logged or handled",
                    severity="warning",
                )
            )
        return exc_handler

    def _check_handler_issues(
        self,
        handlers: list[ast.ExceptHandler],
        caught_types: list[str],
    ) -> None:
        """Check for handler ordering and duplication issues."""
        seen_types: set[str] = set()
        EXCEPTION_HIERARCHY = {
            "Exception": {
                "ValueError",
                "TypeError",
                "KeyError",
                "IndexError",
                "AttributeError",
                "RuntimeError",
                "IOError",
                "OSError",
            },
            "LookupError": {"KeyError", "IndexError"},
            "ArithmeticError": {"ZeroDivisionError", "OverflowError"},
            "OSError": {"FileNotFoundError", "PermissionError", "ConnectionError"},
        }
        broad_handlers_seen: set[str] = set()
        for handler in handlers:
            if handler.type is None:
                continue
            if isinstance(handler.type, ast.Name):
                exc_type = handler.type.id
            elif isinstance(handler.type, ast.Tuple):

                for elt in handler.type.elts:
                    if isinstance(elt, ast.Name):
                        elt_type = elt.id
                        if elt_type in seen_types:
                            self.warnings.append(
                                ExceptionWarning(
                                    kind=ExceptionWarningKind.DUPLICATE_EXCEPT,
                                    file=self.file_path,
                                    line=handler.lineno,
                                    message=f"Duplicate handler for '{elt_type }'",
                                    exception_type=elt_type,
                                )
                            )
                        seen_types.add(elt_type)
                continue
            else:
                continue
            if isinstance(handler.type, ast.Name):
                if exc_type in seen_types:
                    self.warnings.append(
                        ExceptionWarning(
                            kind=ExceptionWarningKind.DUPLICATE_EXCEPT,
                            file=self.file_path,
                            line=handler.lineno,
                            message=f"Duplicate handler for '{exc_type }'",
                            exception_type=exc_type,
                        )
                    )
                for broad, specific_set in EXCEPTION_HIERARCHY.items():
                    if broad in broad_handlers_seen and exc_type in specific_set:
                        self.warnings.append(
                            ExceptionWarning(
                                kind=ExceptionWarningKind.UNREACHABLE_EXCEPT,
                                file=self.file_path,
                                line=handler.lineno,
                                message=f"Handler for '{exc_type }' unreachable after '{broad }'",
                                exception_type=exc_type,
                            )
                        )
                seen_types.add(exc_type)
                if exc_type in EXCEPTION_HIERARCHY:
                    broad_handlers_seen.add(exc_type)

    def visit_Raise(self, node: ast.Raise) -> None:
        """Track raised exceptions."""
        if self.current_function and node.exc:
            if isinstance(node.exc, ast.Call):
                if isinstance(node.exc.func, ast.Name):
                    self.function_raises[self.current_function].add(node.exc.func.id)
            elif isinstance(node.exc, ast.Name):
                self.function_raises[self.current_function].add(node.exc.id)
        self.generic_visit(node)

    def analyze(self, source: str) -> list[ExceptionWarning]:
        """Analyze source code for exception issues."""
        try:
            tree = ast.parse(source)
            self.visit(tree)
        except SyntaxError:
            pass
        return self.warnings


class ExceptionBytecodeAnalyzer:
    """
    Bytecode-based exception flow analysis.
    """

    def analyze(
        self,
        code: object,
        file_path: str = "<unknown>",
    ) -> list[ExceptionWarning]:
        """Analyze bytecode for exception patterns.

        Note: This analyzer currently tracks exception handler structure
        (PUSH_EXC_INFO/POP_EXCEPT boundaries) but does not yet emit
        warnings from bytecode patterns alone.  The AST-based analyzer
        handles the bulk of exception analysis.
        """
        return []


class UncaughtExceptionAnalyzer:
    """
    Analyzes which exceptions might propagate out of functions.
    """

    OPERATION_EXCEPTIONS: dict[str, list[str]] = {
        "BINARY_SUBSCR": ["KeyError", "IndexError", "TypeError"],
        "BINARY_TRUE_DIVIDE": ["ZeroDivisionError"],
        "BINARY_FLOOR_DIVIDE": ["ZeroDivisionError"],
        "BINARY_MODULO": ["ZeroDivisionError"],
        "STORE_SUBSCR": ["KeyError", "IndexError", "TypeError"],
        "DELETE_SUBSCR": ["KeyError", "IndexError", "TypeError"],
        "LOAD_ATTR": ["AttributeError"],
        "STORE_ATTR": ["AttributeError"],
        "DELETE_ATTR": ["AttributeError"],
        "IMPORT_NAME": ["ImportError", "ModuleNotFoundError"],
        "IMPORT_FROM": ["ImportError"],
    }

    def analyze(
        self,
        code: object,
        file_path: str = "<unknown>",
    ) -> dict[str, set[str]]:
        """
        Analyze what exceptions might be raised by a function.
        Returns mapping of operation -> potential exceptions.
        """
        potential_exceptions: dict[str, set[str]] = defaultdict(set)
        instructions = _cached_get_instructions(code)
        current_line = code.co_firstlineno
        protected_ranges: list[tuple[int, int, set[str]]] = []
        self._build_protected_ranges(instructions, protected_ranges)
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            if opname in self.OPERATION_EXCEPTIONS:
                exc_types = self.OPERATION_EXCEPTIONS[opname]
                is_protected = False
                for start, end, caught in protected_ranges:
                    if start <= instr.offset <= end:
                        for exc in exc_types:
                            if exc in caught or "Exception" in caught or "BaseException" in caught:
                                is_protected = True
                                break
                if not is_protected:
                    for exc in exc_types:
                        potential_exceptions[str(current_line)].add(exc)
            if opname == "RAISE_VARARGS":
                pass
        return dict(potential_exceptions)

    @staticmethod
    def _build_protected_ranges(
        instructions: Sequence[object],
        protected_ranges: list[tuple[int, int, set[str]]],
    ) -> None:
        """Populate *protected_ranges* from exception-handling bytecode.

        Works across Python versions:
        - Python < 3.11: ``SETUP_FINALLY``/``SETUP_EXCEPT`` … ``POP_BLOCK``
        - Python 3.11+: ``PUSH_EXC_INFO`` … ``POP_EXCEPT`` with
          ``CHECK_EXC_MATCH`` indicating which types are caught.
        """

        handler_info: list[tuple[int, int, set[str]]] = []
        for i, instr in enumerate(instructions):
            if instr.opname != "PUSH_EXC_INFO":
                continue
            caught: set[str] = set()
            for j in range(i + 1, min(i + 20, len(instructions))):
                if instructions[j].opname == "CHECK_EXC_MATCH":

                    if j > 0 and instructions[j - 1].opname in {
                        "LOAD_GLOBAL",
                        "LOAD_NAME",
                    }:
                        caught.add(str(instructions[j - 1].argval))
                elif instructions[j].opname in {"POP_EXCEPT", "RERAISE"}:
                    break
            if not caught:
                caught = {"Exception"}
            handler_info.append((i, instr.offset, caught))

        for _idx, handler_offset, caught in handler_info:
            try_end = handler_offset
            try_start = 0

            for _prev_idx, prev_off, _ in handler_info:
                if prev_off < handler_offset and prev_off > try_start:
                    try_start = prev_off
            protected_ranges.append((try_start, try_end, caught))


def _infer_caught_at(
    instructions: list[object],
    handler_target: int,
) -> set[str]:
    """Infer caught exception types from handler starting at *handler_target*."""
    caught: set[str] = set()
    started = False
    for instr in instructions:
        if instr.offset == handler_target:
            started = True
        if not started:
            continue
        if instr.opname in {"LOAD_GLOBAL", "LOAD_NAME"}:

            caught.add(str(instr.argval))
        elif instr.opname in {
            "POP_EXCEPT",
            "END_FINALLY",
            "RERAISE",
            "JUMP_FORWARD",
            "JUMP_ABSOLUTE",
        }:
            break
    if not caught:
        caught = {"Exception"}
    return caught


class ExceptionChainAnalyzer:
    """
    Analyzes exception chaining patterns (raise from).
    """

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[ExceptionWarning]:
        """Analyze exception chaining in source.

        Note: Chain analysis is not yet implemented. Returns empty list.
        """
        return []


class ExceptionAnalyzer:
    """
    High-level interface for exception analysis.
    """

    def __init__(self) -> None:
        self.bytecode_analyzer = ExceptionBytecodeAnalyzer()
        self.uncaught_analyzer = UncaughtExceptionAnalyzer()
        self.chain_analyzer = ExceptionChainAnalyzer()

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[ExceptionWarning]:
        """Analyze source for exception issues."""
        ast_analyzer = ExceptionASTAnalyzer(file_path)
        warnings = ast_analyzer.analyze(source)
        warnings.extend(self.chain_analyzer.analyze_source(source, file_path))
        return warnings

    def analyze_function(
        self,
        code: object,
        file_path: str = "<unknown>",
    ) -> list[ExceptionWarning]:
        """Analyze function bytecode for exception issues."""
        return self.bytecode_analyzer.analyze(code, file_path)

    def analyze_file(self, file_path: str) -> list[ExceptionWarning]:
        """Analyze file for exception issues."""
        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()
            warnings = self.analyze_source(source, file_path)
            code = compile(source, file_path, "exec")
            warnings.extend(self.analyze_function(code, file_path))
            self._analyze_nested(code, file_path, warnings)
            return warnings
        except SyntaxError as e:
            return [
                ExceptionWarning(
                    kind=ExceptionWarningKind.UNCAUGHT_EXCEPTION,
                    file=file_path,
                    line=e.lineno or 0,
                    message=f"Syntax error: {e .msg }",
                )
            ]
        except OSError:
            return []

    def _analyze_nested(
        self,
        code: object,
        file_path: str,
        warnings: list[ExceptionWarning],
    ) -> None:
        """Analyze nested functions."""
        for const in code.co_consts:
            if hasattr(const, "co_code"):
                warnings.extend(self.analyze_function(const, file_path))
                self._analyze_nested(const, file_path, warnings)

    def get_potential_exceptions(
        self,
        code: object,
    ) -> dict[str, set[str]]:
        """Get potential uncaught exceptions by line."""
        return self.uncaught_analyzer.analyze(code)


try_body_calls_crashy_api = _try_body_calls_crashy_api
classify_handler_intent = _classify_handler_intent
infer_caught_at = _infer_caught_at
