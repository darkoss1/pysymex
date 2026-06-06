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

"""Source-only adapter for Python ``assert`` statements.

The assert frontend parses source text and normalizes each ``assert`` statement
into ``ContractClauseIR``. It does not import or execute target modules and does
not compile predicates.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from pysymex.contracts.contract_enums import ContractKind, Severity
from pysymex.contracts.frontend.common import UnsupportedFrontendSyntax
from pysymex.contracts.ir.clauses import ContractClauseIR, target_for_source

ASSERT_FRONTEND = "assert"


@dataclass(frozen=True, slots=True)
class _SourceScope:
    """Current source target while walking an AST."""

    name: str
    qualname: str
    line_number: int | None


def assertion_clause_irs_from_source(
    source: str,
    *,
    module: str | None = None,
    filename: str = "<string>",
) -> tuple[ContractClauseIR, ...]:
    """Lower Python ``assert`` statements from source into clause IR."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise UnsupportedFrontendSyntax(
            ASSERT_FRONTEND,
            "source could not be parsed",
            line_number=exc.lineno,
        ) from exc
    collector = _AssertionCollector(module)
    collector.visit(tree)
    return tuple(collector.clauses)


class _AssertionCollector(ast.NodeVisitor):
    """Collect assert clauses while tracking source scopes."""

    def __init__(self, module: str | None) -> None:
        """Initialize the collector for one source module."""
        self.module = module
        self.scopes: list[_SourceScope] = [_SourceScope("<module>", "<module>", None)]
        self.clauses: list[ContractClauseIR] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class scope and collect nested assertions."""
        self._visit_scope(node.name, node.lineno, node.body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a function scope and collect nested assertions."""
        self._visit_scope(node.name, node.lineno, node.body)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit an async function scope and collect nested assertions."""
        self._visit_scope(node.name, node.lineno, node.body)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Lower one ``assert`` statement into a contract clause."""
        condition = _unparse_expr(node.test, line_number=node.lineno)
        message = _assert_message(node)
        scope = self.scopes[-1]
        target = target_for_source(
            scope.name,
            qualname=scope.qualname,
            module=self.module,
            line_number=scope.line_number,
        )
        self.clauses.append(
            ContractClauseIR(
                clause_id=(
                    target.identity,
                    ContractKind.ASSERT,
                    condition,
                    node.lineno,
                    ASSERT_FRONTEND,
                ),
                target=target,
                kind=ContractKind.ASSERT,
                predicate=condition,
                condition=condition,
                message=message,
                severity=Severity.ERROR,
                line_number=node.lineno,
                frontend=ASSERT_FRONTEND,
            )
        )

    def _visit_scope(
        self,
        name: str,
        line_number: int,
        body: list[ast.stmt],
    ) -> None:
        """Visit statements under a nested source target."""
        parent = self.scopes[-1]
        qualname = name if parent.qualname == "<module>" else f"{parent.qualname}.{name}"
        self.scopes.append(_SourceScope(name, qualname, line_number))
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self.scopes.pop()


def _unparse_expr(node: ast.expr, *, line_number: int | None) -> str:
    """Return normalized source text for an assert expression."""
    try:
        return ast.unparse(node).strip()
    except Exception as exc:
        raise UnsupportedFrontendSyntax(
            ASSERT_FRONTEND,
            "assert expression could not be normalized",
            line_number=line_number,
        ) from exc


def _assert_message(node: ast.Assert) -> str:
    """Return the stable message for an assert clause."""
    if node.msg is None:
        return f"Assertion: {_unparse_expr(node.test, line_number=node.lineno)}"
    if isinstance(node.msg, ast.Constant) and isinstance(node.msg.value, str):
        return node.msg.value
    raise UnsupportedFrontendSyntax(
        ASSERT_FRONTEND,
        "assert messages must be string literals",
        line_number=node.lineno,
    )


__all__ = ["ASSERT_FRONTEND", "assertion_clause_irs_from_source"]
