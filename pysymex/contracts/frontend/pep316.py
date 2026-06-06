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

"""Source-only adapter for PEP 316-style docstring contracts.

This adapter recognizes a conservative subset of PEP 316 docstring clauses:
``pre:``, ``post:``, and ``inv:`` lines. It normalizes supported clauses into
``ContractClauseIR`` and rejects unsupported PEP 316 sections explicitly.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from pysymex.contracts.contract_enums import ContractKind, Severity
from pysymex.contracts.frontend.common import UnsupportedFrontendSyntax
from pysymex.contracts.ir.clauses import ContractClauseIR, target_for_source

PEP316_FRONTEND = "pep316"

_SUPPORTED_SECTION_KINDS = {
    "pre": ContractKind.REQUIRES,
    "post": ContractKind.ENSURES,
    "inv": ContractKind.INVARIANT,
}
_UNSUPPORTED_SECTION_NAMES = frozenset({"raises", "except", "exsures"})


@dataclass(frozen=True, slots=True)
class _SourceScope:
    """Current source target while walking an AST."""

    name: str
    qualname: str
    line_number: int | None


@dataclass(frozen=True, slots=True)
class _DocstringClause:
    """One parsed PEP 316 docstring clause."""

    kind: ContractKind
    condition: str
    line_number: int | None


def pep316_clause_irs_from_source(
    source: str,
    *,
    module: str | None = None,
    filename: str = "<string>",
) -> tuple[ContractClauseIR, ...]:
    """Lower supported PEP 316 docstring clauses from source into clause IR."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise UnsupportedFrontendSyntax(
            PEP316_FRONTEND,
            "source could not be parsed",
            line_number=exc.lineno,
        ) from exc
    collector = _Pep316Collector(module)
    collector.visit(tree)
    return tuple(collector.clauses)


class _Pep316Collector(ast.NodeVisitor):
    """Collect PEP 316 clauses while tracking source scopes."""

    def __init__(self, module: str | None) -> None:
        """Initialize the collector for one source module."""
        self.module = module
        self.scopes: list[_SourceScope] = [_SourceScope("<module>", "<module>", None)]
        self.clauses: list[ContractClauseIR] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class docstrings and nested definitions."""
        self._visit_scope(node.name, node.lineno, node.body)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function docstrings and nested definitions."""
        self._visit_scope(node.name, node.lineno, node.body)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function docstrings and nested definitions."""
        self._visit_scope(node.name, node.lineno, node.body)

    def _visit_scope(
        self,
        name: str,
        line_number: int,
        body: list[ast.stmt],
    ) -> None:
        """Visit a scoped definition and lower its docstring clauses."""
        parent = self.scopes[-1]
        qualname = name if parent.qualname == "<module>" else f"{parent.qualname}.{name}"
        scope = _SourceScope(name, qualname, line_number)
        self.scopes.append(scope)
        try:
            self._collect_docstring(body, scope)
            for statement in body:
                self.visit(statement)
        finally:
            self.scopes.pop()

    def _collect_docstring(self, body: list[ast.stmt], scope: _SourceScope) -> None:
        """Append PEP 316 clauses from the first statement docstring."""
        if not body:
            return
        first = body[0]
        if not (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            return
        docstring = first.value.value
        for clause in _parse_docstring_clauses(docstring, base_line=first.lineno):
            self.clauses.append(_clause_ir_for_docstring_clause(clause, scope, self.module))


def _parse_docstring_clauses(
    docstring: str,
    *,
    base_line: int,
) -> tuple[_DocstringClause, ...]:
    """Parse supported one-line PEP 316 clauses from a docstring."""
    clauses: list[_DocstringClause] = []
    for offset, raw_line in enumerate(docstring.splitlines()):
        line_number = base_line + offset
        stripped = raw_line.strip()
        if not stripped:
            continue
        section, separator, condition = stripped.partition(":")
        if not separator:
            continue
        section_name = section.strip()
        if section_name in _SUPPORTED_SECTION_KINDS:
            normalized = condition.strip()
            if not normalized:
                raise UnsupportedFrontendSyntax(
                    PEP316_FRONTEND,
                    f"{section_name}: clause requires a condition",
                    line_number=line_number,
                )
            clauses.append(
                _DocstringClause(
                    kind=_SUPPORTED_SECTION_KINDS[section_name],
                    condition=normalized,
                    line_number=line_number,
                )
            )
            continue
        if section_name in _UNSUPPORTED_SECTION_NAMES or section_name.startswith("post["):
            raise UnsupportedFrontendSyntax(
                PEP316_FRONTEND,
                f"{section_name}: clauses are not supported yet",
                line_number=line_number,
            )
    return tuple(clauses)


def _clause_ir_for_docstring_clause(
    clause: _DocstringClause,
    scope: _SourceScope,
    module: str | None,
) -> ContractClauseIR:
    """Build clause IR for one parsed docstring clause."""
    target = target_for_source(
        scope.name,
        qualname=scope.qualname,
        module=module,
        line_number=scope.line_number,
    )
    return ContractClauseIR(
        clause_id=(
            target.identity,
            clause.kind,
            clause.condition,
            clause.line_number,
            PEP316_FRONTEND,
        ),
        target=target,
        kind=clause.kind,
        predicate=clause.condition,
        condition=clause.condition,
        message=f"PEP 316 {clause.kind.name.lower()}: {clause.condition}",
        severity=Severity.ERROR,
        line_number=clause.line_number,
        frontend=PEP316_FRONTEND,
    )


__all__ = ["PEP316_FRONTEND", "pep316_clause_irs_from_source"]
