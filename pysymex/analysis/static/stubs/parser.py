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

"""Parse Python ``.pyi`` stub files into internal type representations."""

from __future__ import annotations

import ast
from pathlib import Path

from pysymex.analysis.static.stubs.types import ClassStub, FunctionStub, ModuleStub, StubType
from pysymex.logger import get_logger

logger = get_logger(__name__)


class StubParser:
    """
    Parser for Python stub files (.pyi).
    """

    def __init__(self) -> None:
        self._current_module: str = ""
        self._type_aliases: dict[str, StubType] = {}

    def parse_file(self, path: str) -> ModuleStub:
        """Parse a stub file and return the module stub."""
        with open(path, encoding="utf-8") as f:
            source = f.read()
        module_name = Path(path).stem
        if module_name == "__init__":
            module_name = Path(path).parent.name
        return self.parse_source(source, module_name)

    def parse_source(self, source: str, module_name: str) -> ModuleStub:
        """Parse stub source code."""
        self._current_module = module_name
        self._type_aliases = {}
        try:
            tree = ast.parse(source)
        except SyntaxError:
            logger.debug(
                "Failed to parse type stub source for module %s", module_name, exc_info=True
            )
            return ModuleStub(name=module_name)
        stub = ModuleStub(name=module_name)
        for node in ast.iter_child_nodes(tree):
            self._process_node(node, stub)
        return stub

    def _process_node(self, node: ast.AST, stub: ModuleStub) -> None:
        """Process a top-level AST node."""
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            func_stub = self._parse_function(node)
            stub.functions[func_stub.name] = func_stub
        elif isinstance(node, ast.ClassDef):
            class_stub = self._parse_class(node)
            stub.classes[class_stub.name] = class_stub
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                name = node.target.id
                if node.annotation:
                    stub_type = self._parse_type(node.annotation)
                    stub.variables[name] = stub_type
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if isinstance(node.value, (ast.Subscript, ast.Name, ast.Attribute, ast.BinOp)):
                        stub_type = self._parse_type(node.value)
                        stub.type_aliases[target.id] = stub_type
                        self._type_aliases[target.id] = stub_type
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            self._process_import(node, stub)

    def _parse_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionStub:
        """Parse a function definition."""
        func = FunctionStub(name=node.name)
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name == "staticmethod":
                func.is_staticmethod = True
            elif dec_name == "classmethod":
                func.is_classmethod = True
            elif dec_name == "property":
                func.is_property = True
            elif dec_name == "abstractmethod":
                func.is_abstractmethod = True
            elif dec_name == "overload":
                func.is_overload = True
        for arg in node.args.args:
            if arg.annotation:
                func.params[arg.arg] = self._parse_type(arg.annotation)
            else:
                func.params[arg.arg] = StubType.any_type()
        if node.args.vararg:
            arg = node.args.vararg
            if arg.annotation:
                func.params["*" + arg.arg] = self._parse_type(arg.annotation)
        if node.args.kwarg:
            arg = node.args.kwarg
            if arg.annotation:
                func.params["**" + arg.arg] = self._parse_type(arg.annotation)
        if node.returns:
            func.return_type = self._parse_type(node.returns)
        return func

    def _parse_class(self, node: ast.ClassDef) -> ClassStub:
        """Parse a class definition."""
        cls = ClassStub(name=node.name)
        for base in node.bases:
            base_type = self._parse_type(base)
            cls.bases.append(base_type)
            if base_type.name == "Protocol":
                cls.is_protocol = True
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name == "final":
                cls.is_final = True
            elif dec_name == "dataclass":
                cls.is_dataclass = True
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                method = self._parse_function(item)
                cls.methods[method.name] = method
            elif isinstance(item, ast.AnnAssign):
                if isinstance(item.target, ast.Name):
                    name = item.target.id
                    if item.annotation:
                        attr_type = self._parse_type(item.annotation)
                        cls.attributes[name] = attr_type
        return cls

    def _parse_type(self, node: ast.AST) -> StubType:
        """Parse a type annotation AST node."""
        if isinstance(node, ast.Name):
            name = node.id
            if name in self._type_aliases:
                return self._type_aliases[name]
            if name == "None":
                return StubType.none_type()
            elif name == "int":
                return StubType.int_type()
            elif name == "str":
                return StubType.str_type()
            elif name == "bool":
                return StubType.bool_type()
            elif name == "float":
                return StubType.float_type()
            elif name == "bytes":
                return StubType.bytes_type()
            elif name == "object":
                return StubType.object_type()
            return StubType(name=name, module=self._current_module)
        elif isinstance(node, ast.Subscript):
            base_type = self._parse_type(node.value)
            if isinstance(node.slice, ast.Tuple):
                type_args = tuple(self._parse_type(elt) for elt in node.slice.elts)
            else:
                type_args = (self._parse_type(node.slice),)
            if base_type.name == "Optional":
                return StubType(
                    name="Optional",
                    module="typing",
                    type_args=type_args,
                    is_optional=True,
                )
            elif base_type.name == "Union":
                return StubType(
                    name="Union",
                    module="typing",
                    type_args=type_args,
                    is_union=True,
                    union_members=type_args,
                )
            elif base_type.name == "Literal":
                values: list[object] = []
                for arg in type_args:
                    if hasattr(arg, "literal_values"):
                        values.extend(arg.literal_values)
                return StubType(
                    name="Literal",
                    module="typing",
                    is_literal=True,
                    literal_values=tuple(values),
                )
            elif base_type.name == "Callable":
                if len(type_args) >= 2:
                    first_arg = type_args[0]
                    if first_arg.name == "_ParamList":
                        param_types = first_arg.type_args
                    else:
                        param_types = type_args[:-1]
                    return_type = type_args[-1]
                    return StubType(
                        name="Callable",
                        module="typing",
                        is_callable=True,
                        param_types=param_types,
                        return_type=return_type,
                    )
            return StubType(
                name=base_type.name,
                module=base_type.module,
                type_args=type_args,
            )
        elif isinstance(node, ast.Attribute):
            module = self._get_full_name(node.value)
            return StubType(name=node.attr, module=module)
        elif isinstance(node, ast.Constant):
            return StubType(
                name="Literal",
                module="typing",
                is_literal=True,
                literal_values=(node.value,),
            )
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self._parse_type(node.left)
            right = self._parse_type(node.right)
            members: list[StubType] = []
            for t in (left, right):
                if t.is_union:
                    members.extend(t.union_members)
                else:
                    members.append(t)
            return StubType(
                name="Union",
                module="typing",
                is_union=True,
                union_members=tuple(members),
            )
        elif isinstance(node, ast.List):
            return StubType(
                name="_ParamList",
                module="typing",
                type_args=tuple(self._parse_type(elt) for elt in node.elts),
            )
        return StubType.any_type()

    def _get_decorator_name(self, node: ast.AST) -> str:
        """Get the name of a decorator."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Call):
            return self._get_decorator_name(node.func)
        return ""

    def _get_full_name(self, node: ast.AST) -> str:
        """Get full dotted name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_full_name(node.value)}.{node.attr}"
        return ""

    def _process_import(
        self,
        node: ast.Import | ast.ImportFrom,
        stub: ModuleStub,
    ) -> None:
        """Process import statements."""
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                stub.imports[name] = alias.name
        else:
            module = node.module or ""
            for alias in node.names:
                name = alias.asname or alias.name
                full_name = f"{module}.{alias.name}" if module else alias.name
                stub.imports[name] = full_name


__all__ = ["StubParser"]
