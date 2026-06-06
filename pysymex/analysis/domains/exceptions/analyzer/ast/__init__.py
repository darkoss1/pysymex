# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""AST-based exception-flow analysis for source-level handler coverage."""

from __future__ import annotations

import ast
from collections import defaultdict

from pysymex.analysis.domains.exceptions.analyzer.ast.handlers import ExceptionASTHandlerMixin
from pysymex.analysis.domains.exceptions.analyzer.ast.helpers import try_body_calls_crashy_api
from pysymex.analysis.domains.exceptions.types import (
    ExceptionWarning,
    ExceptionWarningKind,
    TryBlock,
)
from pysymex.logger import get_logger

logger = get_logger(__name__)


class ExceptionASTAnalyzer(ExceptionASTHandlerMixin, ast.NodeVisitor):
    """AST-based exception analysis."""

    def __init__(self, file_path: str) -> None:
        """Initialize the ExceptionASTAnalyzer.

        Args:
            file_path (str): The path to the file being analyzed.
        """
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

        calls_crashy = try_body_calls_crashy_api(node)
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
            logger.debug("Exception AST analyzer could not parse source", exc_info=True)
        return self.warnings


__all__ = ["ExceptionASTAnalyzer"]
