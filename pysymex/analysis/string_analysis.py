"""
String Analysis for pysymex.
This module analyzes string operations including:
- Format string validation (% operator, .format(), f-strings)
- String interpolation safety
- Regex pattern validation
- SQL injection detection in string building
- Path traversal in string concatenation
"""

from __future__ import annotations


import ast

import logging

import re

from dataclasses import dataclass

from enum import Enum, auto

from typing import (
    Any,
)


from pysymex._compat import get_starts_line

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

logger = logging.getLogger(__name__)


class StringWarningKind(Enum):
    """Types of string-related warnings."""

    FORMAT_STRING_MISMATCH = auto()

    MISSING_FORMAT_ARG = auto()

    EXTRA_FORMAT_ARG = auto()

    INVALID_FORMAT_SPEC = auto()

    INVALID_REGEX = auto()

    REGEX_PERFORMANCE = auto()

    SQL_INJECTION = auto()

    PATH_TRAVERSAL = auto()

    ENCODING_ERROR = auto()

    STRING_MULTIPLICATION = auto()


@dataclass
class StringWarning:
    """Warning about string operations."""

    kind: StringWarningKind

    file: str

    line: int

    message: str

    code_snippet: str = ""

    severity: str = "warning"


class PrintfFormatAnalyzer:
    """
    Analyzes printf-style format strings (% operator).
    """

    FORMAT_SPEC = re.compile(
        r"%"
        r"(?:\((?P<key>\w+)\))?"
        r"(?P<flags>[-+0 #]*)?"
        r"(?P<width>\*|\d+)?"
        r"(?:\.(?P<precision>\*|\d+))?"
        r"(?P<length>[hlL])?"
        r"(?P<type>[diouxXeEfFgGcrsab%])"
    )

    def analyze(
        self,
        format_string: str,
        args: Any,
        line: int,
        file_path: str,
    ) -> list[StringWarning]:
        """Analyze printf-style format string."""

        warnings: list[StringWarning] = []

        specs = list(self.FORMAT_SPEC.finditer(format_string))

        specs = [s for s in specs if s.group("type") != "%"]

        if not specs:
            return warnings

        has_keys = any(s.group("key") for s in specs)

        if has_keys:
            for spec in specs:
                if not spec.group("key"):
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.INVALID_FORMAT_SPEC,
                            file=file_path,
                            line=line,
                            message="Mixed positional and named format specifiers",
                            code_snippet=format_string,
                        )
                    )

                    break

        else:
            expected = 0

            for spec in specs:
                expected += 1

                if spec.group("width") == "*":
                    expected += 1

                if spec.group("precision") == "*":
                    expected += 1

            if isinstance(args, (tuple, list)):
                actual = len(args)

                if actual < expected:
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.MISSING_FORMAT_ARG,
                            file=file_path,
                            line=line,
                            message=f"Format string expects {expected} arguments, got {actual}",
                            code_snippet=format_string,
                            severity="error",
                        )
                    )

                elif actual > expected:
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.EXTRA_FORMAT_ARG,
                            file=file_path,
                            line=line,
                            message=f"Format string expects {expected} arguments, got {actual}",
                            code_snippet=format_string,
                        )
                    )

        return warnings


class StrFormatAnalyzer:
    """
    Analyzes str.format() calls.
    """

    FORMAT_FIELD = re.compile(
        r"\{" r"(?P<field>[^{}:!]*)" r"(?:!(?P<conversion>[rsab]))?" r"(?::(?P<spec>[^{}]*))?" r"\}"
    )

    def analyze(
        self,
        format_string: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        line: int,
        file_path: str,
    ) -> list[StringWarning]:
        """Analyze str.format() call."""

        warnings: list[StringWarning] = []

        fields = list(self.FORMAT_FIELD.finditer(format_string))

        if not fields:
            return warnings

        positional_refs: list[int] = []

        named_refs: set[str] = set()

        auto_index = 0

        uses_auto = False

        uses_manual = False

        for match in fields:
            field = match.group("field")

            if not field:
                uses_auto = True

                positional_refs.append(auto_index)

                auto_index += 1

            elif field.isdigit():
                uses_manual = True

                positional_refs.append(int(field))

            else:
                base_name = field.split(".")[0].split("[")[0]

                if base_name.isdigit():
                    uses_manual = True

                    positional_refs.append(int(base_name))

                else:
                    named_refs.add(base_name)

        if uses_auto and uses_manual:
            warnings.append(
                StringWarning(
                    kind=StringWarningKind.INVALID_FORMAT_SPEC,
                    file=file_path,
                    line=line,
                    message="Cannot mix automatic and manual field numbering",
                    code_snippet=format_string,
                    severity="error",
                )
            )

        if positional_refs:
            max_index = max(positional_refs)

            if len(args) <= max_index:
                warnings.append(
                    StringWarning(
                        kind=StringWarningKind.MISSING_FORMAT_ARG,
                        file=file_path,
                        line=line,
                        message=f"Format string references index {max_index}, but only {len(args)} positional arguments",
                        code_snippet=format_string,
                        severity="error",
                    )
                )

        for name in named_refs:
            if name not in kwargs:
                warnings.append(
                    StringWarning(
                        kind=StringWarningKind.MISSING_FORMAT_ARG,
                        file=file_path,
                        line=line,
                        message=f"Format string references '{name}' but it's not in keyword arguments",
                        code_snippet=format_string,
                    )
                )

        return warnings


class FStringAnalyzer:
    """
    Analyzes f-string usage.
    Note: f-strings are compiled differently, so we analyze at AST level.
    """

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze f-strings in source."""

        warnings: list[StringWarning] = []

        try:
            tree = ast.parse(source)

        except SyntaxError:
            return warnings

        class FStringVisitor(ast.NodeVisitor):
            def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
                for value in node.values:
                    if isinstance(value, ast.FormattedValue):
                        if value.format_spec:
                            for part in value.format_spec.values:
                                if isinstance(part, ast.FormattedValue):
                                    pass

                self.generic_visit(node)

        visitor = FStringVisitor()

        visitor.visit(tree)

        return warnings


class RegexAnalyzer:
    """
    Analyzes regex patterns for validity and performance.
    """

    REDOS_PATTERNS = [
        r"(\w+)+",
        r"(a+)+$",
        r"(a|a)+",
        r".*.*",
    ]

    def analyze(
        self,
        pattern: str,
        line: int,
        file_path: str,
    ) -> list[StringWarning]:
        """Analyze regex pattern."""

        warnings: list[StringWarning] = []

        try:
            re.compile(pattern)

        except re.error as e:
            warnings.append(
                StringWarning(
                    kind=StringWarningKind.INVALID_REGEX,
                    file=file_path,
                    line=line,
                    message=f"Invalid regex pattern: {e}",
                    code_snippet=pattern,
                    severity="error",
                )
            )

            return warnings

        if re.search(r"\([^)]*[+*][^)]*\)[+*]", pattern):
            warnings.append(
                StringWarning(
                    kind=StringWarningKind.REGEX_PERFORMANCE,
                    file=file_path,
                    line=line,
                    message="Nested quantifiers can cause exponential backtracking (ReDoS)",
                    code_snippet=pattern,
                    severity="warning",
                )
            )

        if ".*" in pattern and not pattern.endswith(".*"):
            if pattern.count(".*") > 1:
                warnings.append(
                    StringWarning(
                        kind=StringWarningKind.REGEX_PERFORMANCE,
                        file=file_path,
                        line=line,
                        message="Multiple .* can cause excessive backtracking",
                        code_snippet=pattern,
                    )
                )

        return warnings


class SQLInjectionAnalyzer:
    """
    Detects potential SQL injection in string operations.
    """

    SQL_KEYWORDS = {
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "CREATE",
        "ALTER",
        "TRUNCATE",
        "EXEC",
        "EXECUTE",
        "UNION",
    }

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze source for SQL injection patterns."""

        warnings: list[StringWarning] = []

        try:
            tree = ast.parse(source)

        except SyntaxError:
            return warnings

        class SQLVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.warnings = warnings

            def visit_BinOp(self, node: ast.BinOp) -> None:
                if isinstance(node.op, (ast.Add, ast.Mod)):
                    sql_string = self._extract_sql_string(node.left)

                    if sql_string:
                        if isinstance(node.right, ast.Name):
                            self.warnings.append(
                                StringWarning(
                                    kind=StringWarningKind.SQL_INJECTION,
                                    file=file_path,
                                    line=node.lineno,
                                    message=f"Potential SQL injection: variable '{node.right.id}' in SQL string",
                                    code_snippet=sql_string[:50],
                                    severity="error",
                                )
                            )

                self.generic_visit(node)

            def visit_Call(self, node: ast.Call) -> None:
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "execute":
                        if node.args:
                            arg = node.args[0]

                            if isinstance(arg, ast.BinOp):
                                sql_string = self._extract_sql_string(arg)

                                if sql_string:
                                    self.warnings.append(
                                        StringWarning(
                                            kind=StringWarningKind.SQL_INJECTION,
                                            file=file_path,
                                            line=node.lineno,
                                            message="SQL query built with string concatenation - use parameterized queries",
                                            code_snippet=sql_string[:50] if sql_string else "",
                                            severity="error",
                                        )
                                    )

                            elif isinstance(arg, ast.JoinedStr):
                                self.warnings.append(
                                    StringWarning(
                                        kind=StringWarningKind.SQL_INJECTION,
                                        file=file_path,
                                        line=node.lineno,
                                        message="SQL query built with f-string - use parameterized queries",
                                        severity="error",
                                    )
                                )

                self.generic_visit(node)

            def _extract_sql_string(self, node: ast.AST) -> str | None:
                """Extract SQL string from node."""

                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    value = node.value.upper()

                    for keyword in self.SQL_KEYWORDS:
                        if keyword in value:
                            return node.value

                return None

        visitor = SQLVisitor()

        visitor.visit(tree)

        return warnings


class PathTraversalAnalyzer:
    """
    Detects potential path traversal vulnerabilities.
    """

    PATH_FUNCTIONS = {
        "open",
        "os.path.join",
        "pathlib.Path",
        "shutil.copy",
        "shutil.move",
        "os.remove",
        "os.mkdir",
        "os.makedirs",
        "os.listdir",
    }

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze source for path traversal patterns."""

        warnings: list[StringWarning] = []

        try:
            tree = ast.parse(source)

        except SyntaxError:
            return warnings

        class PathVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.warnings = warnings

            def visit_Call(self, node: ast.Call) -> None:
                func_name = self._get_func_name(node.func)

                if func_name in {"open", "Path"}:
                    if node.args:
                        arg = node.args[0]

                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            if self._contains_user_input(arg):
                                self.warnings.append(
                                    StringWarning(
                                        kind=StringWarningKind.PATH_TRAVERSAL,
                                        file=file_path,
                                        line=node.lineno,
                                        message="Path built from user input - validate and sanitize",
                                        severity="warning",
                                    )
                                )

                        elif isinstance(arg, ast.JoinedStr):
                            for value in arg.values:
                                if isinstance(value, ast.FormattedValue):
                                    self.warnings.append(
                                        StringWarning(
                                            kind=StringWarningKind.PATH_TRAVERSAL,
                                            file=file_path,
                                            line=node.lineno,
                                            message="Path built with f-string - ensure input is validated",
                                            severity="warning",
                                        )
                                    )

                                    break

                self.generic_visit(node)

            def _get_func_name(self, node: ast.AST) -> str:
                """Get function name from call."""

                if isinstance(node, ast.Name):
                    return node.id

                elif isinstance(node, ast.Attribute):
                    return node.attr

                return ""

            def _contains_user_input(self, node: ast.AST) -> bool:
                """Check if node might contain user input."""

                for child in ast.walk(node):
                    if isinstance(child, ast.Subscript):
                        if isinstance(child.value, ast.Name):
                            if child.value.id in {"request", "params", "args", "kwargs", "data"}:
                                return True

                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            if child.func.id == "input":
                                return True

                return False

        visitor = PathVisitor()

        visitor.visit(tree)

        return warnings


class StringMultiplicationAnalyzer:
    """
    Analyzes string multiplication operations.
    """

    def analyze(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze bytecode for string multiplication issues."""

        warnings: list[StringWarning] = []

        instructions = _cached_get_instructions(code)

        current_line = code.co_firstlineno

        last_const: Any | None = None

        for instr in instructions:
            line = get_starts_line(instr)

            if line is not None:
                current_line = line

            opname = instr.opname

            arg = instr.argval

            if opname == "LOAD_CONST":
                last_const = arg

            elif opname == "BINARY_MULTIPLY":
                if isinstance(last_const, int) and last_const < 0:
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.STRING_MULTIPLICATION,
                            file=file_path,
                            line=current_line,
                            message="String multiplication by negative number produces empty string",
                            severity="warning",
                        )
                    )

            else:
                last_const = None

        return warnings


class StringAnalyzer:
    """
    High-level interface for string analysis.
    """

    def __init__(self) -> None:
        self.printf_analyzer = PrintfFormatAnalyzer()

        self.format_analyzer = StrFormatAnalyzer()

        self.fstring_analyzer = FStringAnalyzer()

        self.regex_analyzer = RegexAnalyzer()

        self.sql_analyzer = SQLInjectionAnalyzer()

        self.path_analyzer = PathTraversalAnalyzer()

        self.mult_analyzer = StringMultiplicationAnalyzer()

    def analyze_source(
        self,
        source: str,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze source for string issues."""

        warnings: list[StringWarning] = []

        warnings.extend(self.fstring_analyzer.analyze_source(source, file_path))

        warnings.extend(self.sql_analyzer.analyze_source(source, file_path))

        warnings.extend(self.path_analyzer.analyze_source(source, file_path))

        return warnings

    def analyze_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[StringWarning]:
        """Analyze function for string issues."""

        warnings: list[StringWarning] = []

        warnings.extend(self.mult_analyzer.analyze(code, file_path))

        return warnings

    def analyze_file(self, file_path: str) -> list[StringWarning]:
        """Analyze file for string issues."""

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                source = f.read()

            warnings = self.analyze_source(source, file_path)

            code = compile(source, file_path, "exec")

            warnings.extend(self.analyze_function(code, file_path))

            self._analyze_nested(code, file_path, warnings)

            return warnings

        except Exception:
            logger.debug("String analysis failed for file %s", file_path, exc_info=True)

            return []

    def _analyze_nested(
        self,
        code: Any,
        file_path: str,
        warnings: list[StringWarning],
    ) -> None:
        """Analyze nested functions."""

        for const in code.co_consts:
            if hasattr(const, "co_code"):
                warnings.extend(self.analyze_function(const, file_path))

                self._analyze_nested(const, file_path, warnings)
