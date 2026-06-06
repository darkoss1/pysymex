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

"""Orchestrate bytecode and AST exception-flow analysis passes."""

from __future__ import annotations

from collections.abc import Callable
from types import CodeType
from typing import TypeVar

from pysymex.analysis.domains.exceptions.analyzer.ast import ExceptionASTAnalyzer
from pysymex.analysis.domains.exceptions.analyzer.bytecode import ExceptionBytecodeAnalyzer
from pysymex.analysis.domains.exceptions.analyzer.chain import ExceptionChainAnalyzer
from pysymex.analysis.domains.exceptions.analyzer.uncaught import UncaughtExceptionAnalyzer
from pysymex.analysis.domains.exceptions.types import ExceptionWarning, ExceptionWarningKind
from pysymex.logger import get_logger

WarningT = TypeVar("WarningT")
logger = get_logger(__name__)


def analyze_nested_code_objects(
    code: CodeType,
    file_path: str,
    warnings: list[WarningT],
    analyze_function: Callable[[CodeType, str], list[WarningT]],
) -> None:
    """Analyze nested code objects with the supplied bytecode analyzer."""
    for const in code.co_consts:
        if hasattr(const, "co_code"):
            warnings.extend(analyze_function(const, file_path))
            analyze_nested_code_objects(const, file_path, warnings, analyze_function)


class ExceptionAnalyzer:
    """High-level interface for exception analysis."""

    def __init__(self) -> None:
        """Initialize the ExceptionAnalyzer, setting up bytecode, uncaught exception, and chain analyzers."""
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
        code: CodeType,
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
            analyze_nested_code_objects(code, file_path, warnings, self.analyze_function)
            return warnings
        except SyntaxError as e:
            logger.debug("Exception analyzer saw syntax error in %s", file_path, exc_info=True)
            return [
                ExceptionWarning(
                    kind=ExceptionWarningKind.UNCAUGHT_EXCEPTION,
                    file=file_path,
                    line=e.lineno or 0,
                    message=f"Syntax error: {e.msg}",
                )
            ]
        except OSError:
            logger.warning("Exception analyzer could not read file: %s", file_path, exc_info=True)
            return []

    def get_potential_exceptions(
        self,
        code: CodeType,
    ) -> dict[str, set[str]]:
        """Get potential uncaught exceptions by line."""
        return self.uncaught_analyzer.analyze(code)
