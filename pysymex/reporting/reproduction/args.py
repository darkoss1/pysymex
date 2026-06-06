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

"""Argument synthesis helpers for reproduction scripts."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal

from pysymex.logger import get_logger

logger = get_logger(__name__)

TYPE_DEFAULTS = {
    "int": "0",
    "float": "0.0",
    "str": '""',
    "bool": "False",
    "list": "[]",
    "dict": "{}",
    "tuple": "()",
    "set": "set()",
    "bytes": 'b""',
    "NoneType": "None",
}


ParameterKind = Literal[
    "positional",
    "positional_only",
    "keyword_only",
    "var_positional",
    "var_keyword",
]


@dataclass(frozen=True)
class ReproductionParameter:
    """Function parameter metadata needed to synthesize a concrete call."""

    name: str
    type_hint: str | None
    kind: ParameterKind
    default_code: str | None = None
    has_default: bool = False


class ReproductionArgsMixin:
    """Build concrete argument expressions from issue counterexamples."""

    def _get_all_function_args(
        self, source_file: str, func_name: str, class_name: str | None = None
    ) -> list[ReproductionParameter]:
        """Parse source file via AST to get function arguments and type hints.

        Returns:
            Ordered parameters that should be passed to the reproduced call.
        """
        try:
            with open(source_file, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=source_file)
        except (OSError, SyntaxError):
            logger.warning(
                "Failed to inspect reproduction arguments from %s", source_file, exc_info=True
            )
            return []

        class FunctionFinder(ast.NodeVisitor):
            """Visitor for locating function and method definitions in source code."""

            def __init__(self, target_func: str, target_class: str | None = None) -> None:
                self.target_func: str = target_func
                self.target_class: str | None = target_class
                self.found_args: ast.arguments | None = None

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self._visit_function(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self._visit_function(node)

            def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                if self.found_args:
                    return
                if node.name == self.target_func:
                    self.found_args = node.args
                self.generic_visit(node)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                if self.target_class and node.name == self.target_class:
                    for item in node.body:
                        if (
                            isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
                            and item.name == self.target_func
                        ):
                            self.found_args = item.args
                            return
                elif not self.target_class:
                    self.generic_visit(node)

        finder = FunctionFinder(
            func_name, class_name if class_name and "." not in class_name else None
        )
        if class_name and "." in class_name:
            finder = FunctionFinder(func_name)
        finder.visit(tree)
        if finder.found_args is None:
            return []
        return self._parameters_from_ast_args(finder.found_args)

    def _parameters_from_ast_args(self, args: ast.arguments) -> list[ReproductionParameter]:
        positional = list(args.posonlyargs) + list(args.args)
        positional_defaults = self._defaults_for_positional(positional, args.defaults)
        parameters: list[ReproductionParameter] = []

        for arg in args.posonlyargs:
            parameters.append(
                ReproductionParameter(
                    name=arg.arg,
                    type_hint=self._annotation_name(arg.annotation),
                    kind="positional_only",
                    default_code=positional_defaults.get(arg.arg),
                    has_default=arg.arg in positional_defaults,
                )
            )

        for arg in args.args:
            parameters.append(
                ReproductionParameter(
                    name=arg.arg,
                    type_hint=self._annotation_name(arg.annotation),
                    kind="positional",
                    default_code=positional_defaults.get(arg.arg),
                    has_default=arg.arg in positional_defaults,
                )
            )

        for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
            parameters.append(
                ReproductionParameter(
                    name=arg.arg,
                    type_hint=self._annotation_name(arg.annotation),
                    kind="keyword_only",
                    default_code=self._source_for_expr(default),
                    has_default=default is not None,
                )
            )
        if args.vararg is not None:
            parameters.append(
                ReproductionParameter(
                    name=args.vararg.arg,
                    type_hint=self._annotation_name(args.vararg.annotation),
                    kind="var_positional",
                )
            )
        if args.kwarg is not None:
            parameters.append(
                ReproductionParameter(
                    name=args.kwarg.arg,
                    type_hint=self._annotation_name(args.kwarg.annotation),
                    kind="var_keyword",
                )
            )
        return parameters

    def _defaults_for_positional(
        self, args: list[ast.arg], defaults: list[ast.expr]
    ) -> dict[str, str]:
        if not defaults:
            return {}
        default_start = len(args) - len(defaults)
        return {
            arg.arg: default_code
            for arg, default in zip(args[default_start:], defaults, strict=True)
            if (default_code := self._source_for_expr(default)) is not None
        }

    def _annotation_name(self, annotation: ast.expr | None) -> str | None:
        if annotation is None:
            return None
        if isinstance(annotation, ast.Name):
            return annotation.id
        if isinstance(annotation, ast.Attribute):
            return annotation.attr
        if isinstance(annotation, ast.Constant):
            return str(annotation.value)
        return ast.unparse(annotation)

    def _source_for_expr(self, expr: ast.expr | None) -> str | None:
        if expr is None:
            return None
        try:
            return ast.unparse(expr)
        except ValueError:
            return None

    def _build_args_list(
        self,
        counterexample: dict[str, object],
        source_file: str | None = None,
        func_name: str | None = None,
        class_name: str | None = None,
    ) -> list[str]:
        """Convert counterexample dict to list of function argument strings."""
        all_args: list[ReproductionParameter] = []
        if source_file and func_name:
            all_args = self._get_all_function_args(source_file, func_name, class_name)
        args: list[str] = []
        if all_args:
            for parameter in all_args:
                if parameter.name in {"self", "cls"}:
                    continue
                value_code = self._argument_value_code(parameter, counterexample)
                if value_code is None:
                    continue
                if parameter.kind == "var_positional":
                    args.append(f"*{value_code}")
                elif parameter.kind in {"positional_only", "positional"}:
                    args.append(value_code)
                elif parameter.kind == "var_keyword":
                    args.append(f"**{value_code}")
                else:
                    args.append(f"{parameter.name}={value_code}")
        else:
            for name, value in counterexample.items():
                if name == "self":
                    continue
                args.append(f"{name}={self._literal_code(value)}")
        return args

    def _argument_value_code(
        self, parameter: ReproductionParameter, counterexample: dict[str, object]
    ) -> str | None:
        if parameter.name in counterexample:
            return self._literal_code(counterexample[parameter.name])
        if parameter.has_default:
            return None
        if parameter.default_code is not None:
            return parameter.default_code
        if parameter.type_hint in TYPE_DEFAULTS:
            return TYPE_DEFAULTS[parameter.type_hint]
        return "None"

    def _literal_code(self, value: object) -> str:
        literal = repr(value)
        try:
            ast.parse(literal, mode="eval")
        except SyntaxError:
            return "None"
        return literal


__all__ = ["ReproductionArgsMixin", "ReproductionParameter", "TYPE_DEFAULTS"]
