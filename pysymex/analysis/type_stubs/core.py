"""Type stub core — StubParser, StubRepository, StubBasedTypeResolver, BuiltinStubs."""

from __future__ import annotations


import ast

import sys

from pathlib import Path

from typing import Any


from pysymex.analysis.type_stubs.types import ClassStub, FunctionStub, ModuleStub, StubType

__all__ = ["StubParser", "StubRepository", "StubBasedTypeResolver", "BuiltinStubs"]


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
            return ModuleStub(name=module_name)

        stub = ModuleStub(name=module_name)

        for node in ast.iter_child_nodes(tree):
            self._process_node(node, stub)

        return stub

    def _process_node(self, node: ast.AST, stub: ModuleStub) -> None:
        """Process a top-level AST node."""

        if isinstance(node, ast.FunctionDef):
            func_stub = self._parse_function(node)

            stub.functions[func_stub.name] = func_stub

        elif isinstance(node, ast.AsyncFunctionDef):
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
                    if isinstance(node.value, (ast.Subscript, ast.Name, ast.Attribute)):
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
                values: list[Any] = []

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

            for t in [left, right]:
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


class StubRepository:
    """
    Repository for loading and caching type stubs.
    """

    def __init__(self) -> None:
        self._cache: dict[str, ModuleStub] = {}

        self._parser = StubParser()

        self._search_paths: list[Path] = []

        self._setup_search_paths()

    def _setup_search_paths(self) -> None:
        """Set up default search paths for stubs."""

        possible_paths = [
            Path(__file__).parent / "typeshed",
            Path(sys.prefix) / "lib" / "python3" / "typeshed",
            Path.home() / ".typeshed",
        ]

        try:
            import mypy

            mypy_path = Path(mypy.__file__).parent / "typeshed"

            if mypy_path.exists():
                possible_paths.append(mypy_path)

        except ImportError:
            pass

        for path in possible_paths:
            if path.exists() and path.is_dir():
                self._search_paths.append(path)

        for site_path in sys.path:
            p = Path(site_path)

            if p.exists() and p.is_dir():
                self._search_paths.append(p)

    def add_search_path(self, path: str) -> None:
        """Add a search path for stubs."""

        p = Path(path)

        if p.exists() and p.is_dir():
            self._search_paths.insert(0, p)

    def get_stub(self, module_name: str) -> ModuleStub | None:
        """Get stub for a module, loading if necessary."""

        if module_name in self._cache:
            return self._cache[module_name]

        stub = self._load_stub(module_name)

        if stub:
            self._cache[module_name] = stub

        return stub

    def _load_stub(self, module_name: str) -> ModuleStub | None:
        """Load a stub file for a module."""

        parts = module_name.split(".")

        for search_path in self._search_paths:
            stub_path = search_path

            for part in parts:
                stub_path = stub_path / part

            init_stub = stub_path / "__init__.pyi"

            if init_stub.exists():
                return self._parser.parse_file(str(init_stub))

            module_stub = stub_path.with_suffix(".pyi")

            if module_stub.exists():
                return self._parser.parse_file(str(module_stub))

            stubs_dir = search_path / "stubs"

            if stubs_dir.exists():
                stub_path = stubs_dir / module_name.replace(".", "-")

                init_stub = stub_path / "__init__.pyi"

                if init_stub.exists():
                    return self._parser.parse_file(str(init_stub))

        return None

    def get_function_type(
        self,
        module_name: str,
        function_name: str,
    ) -> FunctionStub | None:
        """Get the stub for a function."""

        stub = self.get_stub(module_name)

        if not stub:
            return None

        return stub.functions.get(function_name)

    def get_class_type(
        self,
        module_name: str,
        class_name: str,
    ) -> ClassStub | None:
        """Get the stub for a class."""

        stub = self.get_stub(module_name)

        if not stub:
            return None

        return stub.classes.get(class_name)

    def get_method_type(
        self,
        module_name: str,
        class_name: str,
        method_name: str,
    ) -> FunctionStub | None:
        """Get the stub for a method."""

        class_stub = self.get_class_type(module_name, class_name)

        if not class_stub:
            return None

        return class_stub.methods.get(method_name)


class StubBasedTypeResolver:
    """
    Resolves types using stub information.
    """

    def __init__(self, repository: StubRepository | None = None) -> None:
        self.repository = repository or StubRepository()

    def resolve_function_return(
        self,
        module: str,
        function: str,
        arg_types: list[StubType] | None = None,
    ) -> StubType | None:
        """Resolve the return type of a function call."""

        func = self.repository.get_function_type(module, function)

        if not func:
            return None

        return_type = func.return_type

        if return_type and return_type.is_typevar and arg_types:
            pass

        return return_type

    def resolve_method_return(
        self,
        module: str,
        class_name: str,
        method: str,
        arg_types: list[StubType] | None = None,
    ) -> StubType | None:
        """Resolve the return type of a method call."""

        method_stub = self.repository.get_method_type(module, class_name, method)

        if not method_stub:
            return None

        return method_stub.return_type

    def resolve_attribute(
        self,
        module: str,
        class_name: str,
        attribute: str,
    ) -> StubType | None:
        """Resolve the type of a class attribute."""

        class_stub = self.repository.get_class_type(module, class_name)

        if not class_stub:
            return None

        if attribute in class_stub.attributes:
            return class_stub.attributes[attribute]

        if attribute in class_stub.class_vars:
            return class_stub.class_vars[attribute]

        if attribute in class_stub.methods:
            method = class_stub.methods[attribute]

            if method.is_property:
                return method.return_type

        return None

    def check_assignable(
        self,
        source: StubType,
        target: StubType,
    ) -> bool:
        """Check if source type is assignable to target type."""

        if source.name == "Any" or target.name == "Any":
            return True

        if source.name == "None":
            return target.is_optional or target.name == "None"

        if target.is_union:
            return any(self.check_assignable(source, member) for member in target.union_members)

        if source.is_union:
            return all(self.check_assignable(member, target) for member in source.union_members)

        if target.is_optional:
            if target.type_args:
                inner = target.type_args[0]

                return source.name == "None" or self.check_assignable(source, inner)

        if source.name == target.name:
            if not target.type_args:
                return True

            if len(source.type_args) != len(target.type_args):
                return False

            return all(
                self.check_assignable(s, t)
                for s, t in zip(source.type_args, target.type_args, strict=False)
            )

        subtype_relations = {
            "bool": {"int"},
            "int": {"float", "complex"},
            "float": {"complex"},
            "str": {"object"},
            "list": {"Sequence", "Iterable", "Collection"},
            "dict": {"Mapping", "Collection"},
            "set": {"Set", "Collection"},
        }

        if source.name in subtype_relations:
            if target.name in subtype_relations[source.name]:
                return True

        if target.name == "object":
            return True

        return False


class BuiltinStubs:
    """
    Pre-defined stubs for common built-in types and functions.
    These are always available without loading external stub files.
    """

    @staticmethod
    def get_builtin_module() -> ModuleStub:
        """Get stub for builtins module."""

        stub = ModuleStub(name="builtins")

        stub.functions["len"] = FunctionStub(
            name="len",
            params={"__obj": StubType("Sized", "typing")},
            return_type=StubType.int_type(),
        )

        stub.functions["range"] = FunctionStub(
            name="range",
            params={
                "start": StubType.int_type(),
                "stop": StubType.int_type(),
                "step": StubType.int_type(),
            },
            return_type=StubType("range", "builtins"),
        )

        stub.functions["enumerate"] = FunctionStub(
            name="enumerate",
            params={
                "iterable": StubType("Iterable", "typing", (StubType.typevar("T"),)),
                "start": StubType.int_type(),
            },
            return_type=StubType(
                "Iterator",
                "typing",
                (StubType.tuple_of(StubType.int_type(), StubType.typevar("T")),),
            ),
        )

        stub.functions["zip"] = FunctionStub(
            name="zip",
            params={
                "*iterables": StubType("Iterable", "typing"),
            },
            return_type=StubType("Iterator", "typing", (StubType("tuple", "builtins"),)),
        )

        stub.functions["map"] = FunctionStub(
            name="map",
            params={
                "func": StubType.callable([StubType.typevar("T")], StubType.typevar("S")),
                "*iterables": StubType("Iterable", "typing", (StubType.typevar("T"),)),
            },
            return_type=StubType("Iterator", "typing", (StubType.typevar("S"),)),
        )

        stub.functions["filter"] = FunctionStub(
            name="filter",
            params={
                "func": StubType.optional(
                    StubType.callable([StubType.typevar("T")], StubType.bool_type())
                ),
                "iterable": StubType("Iterable", "typing", (StubType.typevar("T"),)),
            },
            return_type=StubType("Iterator", "typing", (StubType.typevar("T"),)),
        )

        stub.functions["sorted"] = FunctionStub(
            name="sorted",
            params={
                "iterable": StubType("Iterable", "typing", (StubType.typevar("T"),)),
                "key": StubType.optional(
                    StubType.callable([StubType.typevar("T")], StubType.any_type())
                ),
                "reverse": StubType.bool_type(),
            },
            return_type=StubType.list_of(StubType.typevar("T")),
        )

        stub.functions["isinstance"] = FunctionStub(
            name="isinstance",
            params={
                "obj": StubType.object_type(),
                "classinfo": StubType.union(
                    StubType("type", "builtins"),
                    StubType.tuple_of(StubType("type", "builtins")),
                ),
            },
            return_type=StubType.bool_type(),
        )

        stub.functions["hasattr"] = FunctionStub(
            name="hasattr",
            params={
                "obj": StubType.object_type(),
                "name": StubType.str_type(),
            },
            return_type=StubType.bool_type(),
        )

        stub.functions["getattr"] = FunctionStub(
            name="getattr",
            params={
                "obj": StubType.object_type(),
                "name": StubType.str_type(),
                "default": StubType.any_type(),
            },
            return_type=StubType.any_type(),
        )

        return stub

    @staticmethod
    def get_collections_module() -> ModuleStub:
        """Get stub for collections module."""

        stub = ModuleStub(name="collections")

        defaultdict_class = ClassStub(
            name="defaultdict",
            bases=[StubType.dict_of(StubType.typevar("K"), StubType.typevar("V"))],
        )

        defaultdict_class.methods["__getitem__"] = FunctionStub(
            name="__getitem__",
            params={"key": StubType.typevar("K")},
            return_type=StubType.typevar("V"),
        )

        stub.classes["defaultdict"] = defaultdict_class

        counter_class = ClassStub(
            name="Counter",
            bases=[StubType.dict_of(StubType.typevar("T"), StubType.int_type())],
        )

        counter_class.methods["__getitem__"] = FunctionStub(
            name="__getitem__",
            params={"key": StubType.typevar("T")},
            return_type=StubType.int_type(),
        )

        stub.classes["Counter"] = counter_class

        ordered_dict_class = ClassStub(
            name="OrderedDict",
            bases=[StubType.dict_of(StubType.typevar("K"), StubType.typevar("V"))],
        )

        stub.classes["OrderedDict"] = ordered_dict_class

        deque_class = ClassStub(
            name="deque",
            bases=[StubType("MutableSequence", "typing", (StubType.typevar("T"),))],
        )

        deque_class.methods["append"] = FunctionStub(
            name="append",
            params={"x": StubType.typevar("T")},
            return_type=StubType.none_type(),
        )

        deque_class.methods["appendleft"] = FunctionStub(
            name="appendleft",
            params={"x": StubType.typevar("T")},
            return_type=StubType.none_type(),
        )

        stub.classes["deque"] = deque_class

        return stub
