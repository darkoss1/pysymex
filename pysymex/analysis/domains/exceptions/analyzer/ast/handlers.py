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

"""Extract and diagnose exception handler patterns from the AST."""

from __future__ import annotations

import ast

from pysymex.analysis.domains.exceptions.analyzer.ast.helpers import classify_handler_intent
from pysymex.analysis.domains.exceptions.types import (
    ExceptionHandler,
    ExceptionWarning,
    ExceptionWarningKind,
    HandlerIntent,
)


class ExceptionASTHandlerMixin:
    """Handler-analysis methods used by :class:`ExceptionASTAnalyzer`."""

    file_path: str
    warnings: list[ExceptionWarning]

    def _analyze_handler(
        self,
        handler: ast.ExceptHandler,
        *,
        calls_crashy_api: bool = False,
    ) -> ExceptionHandler:
        """Analyze a single exception handler."""
        exc_handler = ExceptionHandler(line=handler.lineno, exception_types=[])

        intent = classify_handler_intent(handler)
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
                            message="Catching 'Exception' is broad, but handler provides recovery",
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
        if (
            not exc_handler.has_logging
            and not exc_handler.has_reraise
            and not exc_handler.has_return
        ):
            self.warnings.append(
                ExceptionWarning(
                    kind=ExceptionWarningKind.EXCEPTION_NOT_LOGGED,
                    file=self.file_path,
                    line=handler.lineno,
                    message="Exception caught but not logged, raised, or returned",
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
        _ = caught_types
        seen_types: set[str] = set()
        exception_hierarchy = {
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
            handler_types: list[str] = []
            if isinstance(handler.type, ast.Name):
                handler_types.append(handler.type.id)
            elif isinstance(handler.type, ast.Tuple):
                for elt in handler.type.elts:
                    if isinstance(elt, ast.Name):
                        handler_types.append(elt.id)
            for exc_type in handler_types:
                if exc_type in seen_types:
                    self.warnings.append(
                        ExceptionWarning(
                            kind=ExceptionWarningKind.DUPLICATE_EXCEPT,
                            file=self.file_path,
                            line=handler.lineno,
                            message=f"Duplicate handler for '{exc_type}'",
                            exception_type=exc_type,
                        )
                    )
                for broad, specific_set in exception_hierarchy.items():
                    if broad in broad_handlers_seen and exc_type in specific_set:
                        self.warnings.append(
                            ExceptionWarning(
                                kind=ExceptionWarningKind.UNREACHABLE_EXCEPT,
                                file=self.file_path,
                                line=handler.lineno,
                                message=f"Handler for '{exc_type}' unreachable after '{broad}'",
                                exception_type=exc_type,
                            )
                        )
                seen_types.add(exc_type)
                if exc_type in exception_hierarchy:
                    broad_handlers_seen.add(exc_type)


__all__ = ["ExceptionASTHandlerMixin"]
