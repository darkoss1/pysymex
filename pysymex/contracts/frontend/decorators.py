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

"""Shared lowering for module-qualified lambda decorator frontends.

This module owns the AST mechanics for decorator syntaxes such as
``@icontract.require(lambda ...)`` and ``@deal.pre(lambda ...)``. Frontend
modules provide the declarative mapping from decorator names to
``ContractKind`` values; this module performs source-only normalization to
``ContractClauseIR``.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass

from pysymex.contracts.contract_enums import ContractKind, Severity
from pysymex.contracts.frontend.common import UnsupportedFrontendSyntax
from pysymex.contracts.ir.clauses import ContractClauseIR, target_for_source


@dataclass(frozen=True, slots=True)
class LambdaDecoratorFrontendSpec:
    """Configuration for one module-qualified lambda decorator frontend."""

    frontend: str
    module_name: str
    kind_by_decorator: Mapping[str, ContractKind]
    message_keyword: str
    message_label: str


@dataclass(frozen=True, slots=True)
class _ParsedLambdaDecorator:
    """One supported lambda decorator normalized from AST."""

    kind: ContractKind
    condition: str
    message: str | None
    line_number: int


def lambda_decorator_clause_irs_from_source(
    source: str,
    spec: LambdaDecoratorFrontendSpec,
    *,
    module: str | None = None,
    filename: str = "<string>",
) -> tuple[ContractClauseIR, ...]:
    """Lower supported module-qualified lambda decorators from source into IR."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise UnsupportedFrontendSyntax(
            spec.frontend,
            "source could not be parsed",
            line_number=exc.lineno,
        ) from exc
    collector = _LambdaDecoratorCollector(spec, module)
    collector.visit(tree)
    return tuple(collector.clauses)


class _LambdaDecoratorCollector(ast.NodeVisitor):
    """Collect supported decorators while tracking source scopes."""

    def __init__(self, spec: LambdaDecoratorFrontendSpec, module: str | None) -> None:
        """Initialize the collector for one source module."""
        self.spec = spec
        self.module = module
        self.scope_stack: list[str] = []
        self.clauses: list[ContractClauseIR] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class decorators and nested definitions."""
        qualname = self._qualname(node.name)
        self._collect_decorators(
            node.name,
            qualname,
            node.lineno,
            node.decorator_list,
            is_class=True,
        )
        self.scope_stack.append(node.name)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function decorators and nested definitions."""
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function decorators and nested definitions."""
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit one function-like definition."""
        qualname = self._qualname(node.name)
        self._collect_decorators(
            node.name,
            qualname,
            node.lineno,
            node.decorator_list,
            is_class=False,
        )
        self.scope_stack.append(node.name)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scope_stack.pop()

    def _collect_decorators(
        self,
        name: str,
        qualname: str,
        target_line: int,
        decorators: list[ast.expr],
        *,
        is_class: bool,
    ) -> None:
        """Collect supported decorators for one class or function definition."""
        for decorator in decorators:
            parsed = _parse_lambda_decorator(decorator, self.spec)
            if parsed is None:
                continue
            if parsed.kind is ContractKind.INVARIANT and not is_class:
                raise UnsupportedFrontendSyntax(
                    self.spec.frontend,
                    "invariant decorators are supported on classes only",
                    line_number=parsed.line_number,
                )
            if parsed.kind is not ContractKind.INVARIANT and is_class:
                raise UnsupportedFrontendSyntax(
                    self.spec.frontend,
                    f"{parsed.kind.name.lower()} decorators are supported on functions only",
                    line_number=parsed.line_number,
                )
            target = target_for_source(
                name,
                qualname=qualname,
                module=self.module,
                line_number=target_line,
            )
            self.clauses.append(
                ContractClauseIR(
                    clause_id=(
                        target.identity,
                        parsed.kind,
                        parsed.condition,
                        parsed.line_number,
                        self.spec.frontend,
                    ),
                    target=target,
                    kind=parsed.kind,
                    predicate=parsed.condition,
                    condition=parsed.condition,
                    message=(
                        parsed.message
                        or f"{self.spec.frontend} {parsed.kind.name.lower()}: {parsed.condition}"
                    ),
                    severity=Severity.ERROR,
                    line_number=parsed.line_number,
                    frontend=self.spec.frontend,
                )
            )

    def _qualname(self, name: str) -> str:
        """Return the current nested source qualname."""
        if not self.scope_stack:
            return name
        return ".".join([*self.scope_stack, name])


def _parse_lambda_decorator(
    decorator: ast.expr,
    spec: LambdaDecoratorFrontendSpec,
) -> _ParsedLambdaDecorator | None:
    """Return normalized decorator data, or ``None`` for other decorators."""
    if not isinstance(decorator, ast.Call):
        return None
    if not (
        isinstance(decorator.func, ast.Attribute)
        and isinstance(decorator.func.value, ast.Name)
        and decorator.func.value.id == spec.module_name
    ):
        return None
    kind = spec.kind_by_decorator.get(decorator.func.attr)
    if kind is None:
        raise UnsupportedFrontendSyntax(
            spec.frontend,
            f"{spec.module_name}.{decorator.func.attr} is not supported",
            line_number=decorator.lineno,
        )
    if not decorator.args or not isinstance(decorator.args[0], ast.Lambda):
        raise UnsupportedFrontendSyntax(
            spec.frontend,
            "decorator condition must be an inline lambda",
            line_number=decorator.lineno,
        )
    if len(decorator.args) > 2:
        raise UnsupportedFrontendSyntax(
            spec.frontend,
            f"decorator accepts only a lambda and optional {spec.message_label}",
            line_number=decorator.lineno,
        )
    message = _decorator_message(decorator, spec)
    condition = _unparse_expr(decorator.args[0].body, spec=spec, line_number=decorator.lineno)
    return _ParsedLambdaDecorator(
        kind=kind,
        condition=condition,
        message=message,
        line_number=decorator.lineno,
    )


def _decorator_message(decorator: ast.Call, spec: LambdaDecoratorFrontendSpec) -> str | None:
    """Return an optional supported decorator message."""
    message: str | None = None
    if len(decorator.args) > 1:
        second_arg = decorator.args[1]
        if not (isinstance(second_arg, ast.Constant) and isinstance(second_arg.value, str)):
            raise UnsupportedFrontendSyntax(
                spec.frontend,
                f"decorator {spec.message_label} must be a string literal",
                line_number=decorator.lineno,
            )
        message = second_arg.value
    for keyword in decorator.keywords:
        if keyword.arg is None:
            raise UnsupportedFrontendSyntax(
                spec.frontend,
                "keyword unpacking is not supported",
                line_number=decorator.lineno,
            )
        if keyword.arg != spec.message_keyword:
            raise UnsupportedFrontendSyntax(
                spec.frontend,
                f"keyword {keyword.arg!r} is not supported",
                line_number=decorator.lineno,
            )
        if message is not None:
            raise UnsupportedFrontendSyntax(
                spec.frontend,
                f"{spec.message_label} specified more than once",
                line_number=decorator.lineno,
            )
        if not (isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str)):
            raise UnsupportedFrontendSyntax(
                spec.frontend,
                f"{spec.message_label} must be a string literal",
                line_number=decorator.lineno,
            )
        message = keyword.value.value
    return message


def _unparse_expr(
    node: ast.expr,
    *,
    spec: LambdaDecoratorFrontendSpec,
    line_number: int | None,
) -> str:
    """Return normalized source text for a decorator lambda body."""
    try:
        return ast.unparse(node).strip()
    except Exception as exc:
        raise UnsupportedFrontendSyntax(
            spec.frontend,
            "decorator lambda could not be normalized",
            line_number=line_number,
        ) from exc


__all__ = ["LambdaDecoratorFrontendSpec", "lambda_decorator_clause_irs_from_source"]
