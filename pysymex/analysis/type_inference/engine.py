"""
Core type inference engine for pysymex.

Contains:
- TypeInferenceEngine: Main engine performing forward type propagation,
  annotation parsing, value inference, and type narrowing for control flow
"""

from __future__ import annotations


import inspect

from collections.abc import Callable

from typing import Any, Union, cast, get_type_hints


from pysymex.analysis.type_inference.env import TypeEnvironment

from pysymex.analysis.type_inference.kinds import PyType, TypeKind


class TypeInferenceEngine:
    """
    Main type inference engine.
    Performs:
    - Forward type propagation
    - Flow-sensitive type narrowing
    - Pattern-based inference
    - Type annotation integration
    """

    def __init__(self) -> None:
        self.environments: dict[int, TypeEnvironment] = {}

        self.function_signatures: dict[str, tuple[list[PyType], PyType]] = {}

        self.class_attributes: dict[str, dict[str, PyType]] = {}

        self._inference_cache: dict[tuple[str, int], PyType] = {}

        self._stub_resolver: Any = None

    @property
    def stub_resolver(self) -> Any:
        """Lazy-load stub resolver to avoid circular imports."""

        if self._stub_resolver is None:
            try:
                from pysymex.analysis.type_stubs import StubBasedTypeResolver

                self._stub_resolver = StubBasedTypeResolver()

            except Exception:
                self._stub_resolver = False

        return self._stub_resolver if self._stub_resolver is not False else None

    def infer_from_annotation(self, annotation: Any) -> PyType:
        """Convert a type annotation to PyType."""

        if annotation is None:
            return PyType.any_()

        if annotation is type(None):
            return PyType.none()

        if annotation is int:
            return PyType.int_()

        if annotation is str:
            return PyType.str_()

        if annotation is float:
            return PyType.float_()

        if annotation is bool:
            return PyType.bool_()

        if annotation is bytes:
            return PyType.bytes_()

        origin = getattr(annotation, "__origin__", None)

        args = getattr(annotation, "__args__", ())

        if origin is list:
            elem_type = self.infer_from_annotation(args[0]) if args else PyType.any_()

            return PyType.list_(elem_type)

        if origin is dict:
            key_type = self.infer_from_annotation(args[0]) if args else PyType.any_()

            val_type = self.infer_from_annotation(args[1]) if len(args) > 1 else PyType.any_()

            return PyType.dict_(key_type, val_type)

        if origin is set:
            elem_type = self.infer_from_annotation(args[0]) if args else PyType.any_()

            return PyType.set_(elem_type)

        if origin is tuple:
            if args:
                elem_types = tuple(self.infer_from_annotation(a) for a in args)

                return PyType.tuple_(*elem_types)

            return PyType.tuple_()

        if origin is Union:
            member_types = [self.infer_from_annotation(a) for a in args]

            return PyType.union_(*member_types)

        if origin is Union and len(args) == 2 and type(None) in args:
            inner = args[0] if args[1] is type(None) else args[1]

            return PyType.optional_(self.infer_from_annotation(inner))

        if isinstance(annotation, str):
            return self._parse_string_annotation(annotation)

        if isinstance(annotation, type):
            return PyType.instance(annotation.__name__)

        return PyType.any_()

    def _parse_string_annotation(self, annotation: str) -> PyType:
        """Parse a string type annotation."""

        annotation = annotation.strip()

        if annotation == "None":
            return PyType.none()

        basic_types = {
            "int": PyType.int_(),
            "str": PyType.str_(),
            "float": PyType.float_(),
            "bool": PyType.bool_(),
            "bytes": PyType.bytes_(),
            "Any": PyType.any_(),
        }

        if annotation in basic_types:
            return basic_types[annotation]

        if annotation.startswith("Optional[") and annotation.endswith("]"):
            inner = annotation[9:-1]

            return PyType.optional_(self._parse_string_annotation(inner))

        if annotation.startswith("list[") and annotation.endswith("]"):
            inner = annotation[5:-1]

            return PyType.list_(self._parse_string_annotation(inner))

        if annotation.startswith("List[") and annotation.endswith("]"):
            inner = annotation[5:-1]

            return PyType.list_(self._parse_string_annotation(inner))

        if annotation.startswith("dict[") or annotation.startswith("Dict["):
            inner = annotation[5:-1] if annotation.startswith("dict[") else annotation[5:-1]

            parts = inner.split(",", 1)

            if len(parts) == 2:
                key_type = self._parse_string_annotation(parts[0].strip())

                val_type = self._parse_string_annotation(parts[1].strip())

                return PyType.dict_(key_type, val_type)

        if annotation.startswith("set[") or annotation.startswith("Set["):
            inner = annotation[4:-1]

            return PyType.set_(self._parse_string_annotation(inner))

        if annotation.startswith("tuple[") or annotation.startswith("Tuple["):
            inner = annotation[6:-1]

            parts = [p.strip() for p in inner.split(",")]

            elem_types = [self._parse_string_annotation(p) for p in parts]

            return PyType.tuple_(*elem_types)

        if annotation.startswith("Union[") and annotation.endswith("]"):
            inner = annotation[6:-1]

            parts = [p.strip() for p in inner.split(",")]

            member_types = [self._parse_string_annotation(p) for p in parts]

            return PyType.union_(*member_types)

        return PyType.instance(annotation)

    def infer_function_signature(self, func: Callable[..., Any]) -> tuple[list[PyType], PyType]:
        """Infer parameter and return types for a function."""

        func_name = getattr(func, "__qualname__", str(func))

        if func_name in self.function_signatures:
            return self.function_signatures[func_name]

        try:
            hints = get_type_hints(func)

        except Exception:
            hints = {}

        stub_func = None

        if not hints and self.stub_resolver:
            module = getattr(func, "__module__", None)

            name = getattr(func, "__name__", None)

            if module and name:
                try:
                    stub_func = self.stub_resolver.repository.get_function_type(module, name)

                except Exception:
                    pass

        sig = inspect.signature(func)

        param_types: list[PyType] = []

        for param_name, param in sig.parameters.items():
            if param_name in hints:
                param_types.append(self.infer_from_annotation(hints[param_name]))

            elif param.default is not inspect.Parameter.empty:
                param_types.append(self.infer_from_value(param.default))

            elif stub_func and param_name in getattr(stub_func, "params", {}):
                stub_type = stub_func.params[param_name]

                param_types.append(
                    stub_type.to_pytype() if hasattr(stub_type, "to_pytype") else PyType.any_()
                )

            else:
                param_types.append(PyType.any_())

        return_type = self.infer_from_annotation(hints.get("return", None))

        if (
            return_type.kind == TypeKind.ANY
            and stub_func
            and getattr(stub_func, "return_type", None)
        ):
            converted = (
                stub_func.return_type.to_pytype()
                if hasattr(stub_func.return_type, "to_pytype")
                else None
            )

            if converted:
                return_type = converted

        self.function_signatures[func_name] = (param_types, return_type)

        return param_types, return_type

    def infer_from_value(self, value: Any) -> PyType:
        """Infer type from a concrete Python value."""

        if value is None:
            return PyType.none()

        if isinstance(value, bool):
            return PyType.literal_(value)

        if isinstance(value, int):
            return PyType.int_()

        if isinstance(value, float):
            return PyType.float_()

        if isinstance(value, str):
            if len(value) <= 50:
                return PyType.literal_(value)

            return PyType.str_()

        if isinstance(value, bytes):
            return PyType.bytes_()

        if isinstance(value, list):
            if not value:
                return PyType.list_()

            _list_val = cast(list[Any], value)

            elem_types = [self.infer_from_value(e) for e in _list_val[:5]]

            combined = elem_types[0]

            for t in elem_types[1:]:
                combined = combined.join(t)

            return PyType.list_(combined)

        if isinstance(value, dict):
            if not value:
                return PyType.dict_()

            _dict_val = cast(dict[Any, Any], value)

            keys: list[Any] = list(_dict_val.keys())[:5]

            vals: list[Any] = list(_dict_val.values())[:5]

            key_types = [self.infer_from_value(k) for k in keys]

            val_types = [self.infer_from_value(v) for v in vals]

            key_type = key_types[0]

            val_type = val_types[0]

            for t in key_types[1:]:
                key_type = key_type.join(t)

            for t in val_types[1:]:
                val_type = val_type.join(t)

            return PyType.dict_(key_type, val_type)

        if isinstance(value, set):
            if not value:
                return PyType.set_()

            _set_val = cast(set[Any], value)

            elem_types = [self.infer_from_value(e) for e in list(_set_val)[:5]]

            combined = elem_types[0]

            for t in elem_types[1:]:
                combined = combined.join(t)

            return PyType.set_(combined)

        if isinstance(value, tuple):
            _tuple_val = cast(tuple[Any, ...], value)

            elem_types = tuple(self.infer_from_value(e) for e in _tuple_val)

            return PyType.tuple_(*elem_types)

        if isinstance(value, frozenset):
            if not value:
                return PyType(kind=TypeKind.FROZENSET, name="frozenset")

            _fset_val = cast(frozenset[Any], value)

            elem_types = [self.infer_from_value(e) for e in list(_fset_val)[:5]]

            combined = elem_types[0]

            for t in elem_types[1:]:
                combined = combined.join(t)

            return PyType(
                kind=TypeKind.FROZENSET,
                name="frozenset",
                params=(combined,),
            )

        if callable(value):
            try:
                param_types, return_type = self.infer_function_signature(value)

                return PyType.callable_(param_types, return_type)

            except Exception:
                return PyType(kind=TypeKind.CALLABLE, name="Callable")

        return PyType.instance(type(value).__name__)

    def infer_binary_op_result(
        self,
        op: str,
        left: PyType,
        right: PyType,
    ) -> PyType:
        """Infer result type of a binary operation."""

        if op in {"+", "-", "*", "/", "//", "%", "**"}:
            if left.is_numeric() and right.is_numeric():
                if op == "/":
                    return PyType.float_()

                if left.kind == TypeKind.COMPLEX or right.kind == TypeKind.COMPLEX:
                    return PyType(kind=TypeKind.COMPLEX, name="complex")

                if left.kind == TypeKind.FLOAT or right.kind == TypeKind.FLOAT:
                    return PyType.float_()

                return PyType.int_()

            if op == "+" and left.kind == TypeKind.STR and right.kind == TypeKind.STR:
                return PyType.str_()

            if op == "*":
                if left.kind == TypeKind.STR and right.kind == TypeKind.INT:
                    return PyType.str_()

                if left.kind == TypeKind.INT and right.kind == TypeKind.STR:
                    return PyType.str_()

                if left.kind == TypeKind.LIST and right.kind == TypeKind.INT:
                    return left

                if left.kind == TypeKind.INT and right.kind == TypeKind.LIST:
                    return right

            if op == "+" and left.kind == TypeKind.LIST and right.kind == TypeKind.LIST:
                elem_type = left.get_element_type().join(right.get_element_type())

                return PyType.list_(elem_type)

        if op in {"==", "!=", "<", ">", "<=", ">=", "is", "is not", "in", "not in"}:
            return PyType.bool_()

        if op in {"&", "|", "^", "<<", ">>", "~"}:
            if left.kind == TypeKind.INT and right.kind == TypeKind.INT:
                return PyType.int_()

            if left.kind == TypeKind.BOOL and right.kind == TypeKind.BOOL:
                return PyType.bool_()

            if left.kind == TypeKind.SET and right.kind == TypeKind.SET:
                return left

        if op in {"and", "or"}:
            return left.join(right)

        return PyType.any_()

    def infer_unary_op_result(self, op: str, operand: PyType) -> PyType:
        """Infer result type of a unary operation."""

        if op == "-":
            if operand.is_numeric():
                return operand

        if op == "+":
            if operand.is_numeric():
                return operand

        if op == "~":
            if operand.kind == TypeKind.INT:
                return PyType.int_()

        if op == "not":
            return PyType.bool_()

        return PyType.any_()

    def infer_subscript_result(
        self,
        container: PyType,
        index: PyType,
    ) -> PyType:
        """Infer result type of a subscript operation."""

        if container.kind in {TypeKind.LIST, TypeKind.DEQUE}:
            return container.get_element_type()

        if container.kind == TypeKind.TUPLE:
            if index.kind == TypeKind.LITERAL and index.literal_values:
                for val in index.literal_values:
                    if isinstance(val, int) and 0 <= val < len(container.params):
                        return container.params[val]

            if container.params:
                return PyType.union_(*container.params)

            return PyType.any_()

        if container.kind in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            return container.get_value_type()

        if container.kind == TypeKind.STR:
            return PyType.str_()

        if container.kind == TypeKind.BYTES:
            return PyType.int_()

        return PyType.any_()

    def infer_attribute_result(
        self,
        obj: PyType,
        attr_name: str,
    ) -> PyType:
        """Infer result type of an attribute access."""

        if attr_name in obj.attributes:
            return obj.attributes[attr_name]

        if obj.kind == TypeKind.STR:
            str_methods = {
                "lower": PyType.callable_([], PyType.str_()),
                "upper": PyType.callable_([], PyType.str_()),
                "strip": PyType.callable_([], PyType.str_()),
                "lstrip": PyType.callable_([], PyType.str_()),
                "rstrip": PyType.callable_([], PyType.str_()),
                "split": PyType.callable_([], PyType.list_(PyType.str_())),
                "rsplit": PyType.callable_([], PyType.list_(PyType.str_())),
                "join": PyType.callable_([PyType.any_()], PyType.str_()),
                "replace": PyType.callable_([PyType.str_(), PyType.str_()], PyType.str_()),
                "find": PyType.callable_([PyType.str_()], PyType.int_()),
                "rfind": PyType.callable_([PyType.str_()], PyType.int_()),
                "index": PyType.callable_([PyType.str_()], PyType.int_()),
                "rindex": PyType.callable_([PyType.str_()], PyType.int_()),
                "count": PyType.callable_([PyType.str_()], PyType.int_()),
                "startswith": PyType.callable_([PyType.str_()], PyType.bool_()),
                "endswith": PyType.callable_([PyType.str_()], PyType.bool_()),
                "isdigit": PyType.callable_([], PyType.bool_()),
                "isalpha": PyType.callable_([], PyType.bool_()),
                "isalnum": PyType.callable_([], PyType.bool_()),
                "isspace": PyType.callable_([], PyType.bool_()),
                "isupper": PyType.callable_([], PyType.bool_()),
                "islower": PyType.callable_([], PyType.bool_()),
                "title": PyType.callable_([], PyType.str_()),
                "capitalize": PyType.callable_([], PyType.str_()),
                "swapcase": PyType.callable_([], PyType.str_()),
                "encode": PyType.callable_([], PyType.bytes_()),
                "format": PyType.callable_([], PyType.str_()),
                "format_map": PyType.callable_([PyType.any_()], PyType.str_()),
                "center": PyType.callable_([PyType.int_()], PyType.str_()),
                "ljust": PyType.callable_([PyType.int_()], PyType.str_()),
                "rjust": PyType.callable_([PyType.int_()], PyType.str_()),
                "zfill": PyType.callable_([PyType.int_()], PyType.str_()),
                "partition": PyType.callable_(
                    [PyType.str_()], PyType.tuple_(PyType.str_(), PyType.str_(), PyType.str_())
                ),
                "rpartition": PyType.callable_(
                    [PyType.str_()], PyType.tuple_(PyType.str_(), PyType.str_(), PyType.str_())
                ),
                "expandtabs": PyType.callable_([], PyType.str_()),
                "splitlines": PyType.callable_([], PyType.list_(PyType.str_())),
                "translate": PyType.callable_([PyType.any_()], PyType.str_()),
                "maketrans": PyType.callable_([], PyType.dict_(PyType.int_(), PyType.any_())),
                "removeprefix": PyType.callable_([PyType.str_()], PyType.str_()),
                "removesuffix": PyType.callable_([PyType.str_()], PyType.str_()),
            }

            if attr_name in str_methods:
                return str_methods[attr_name]

        if obj.kind == TypeKind.LIST:
            elem_type = obj.get_element_type()

            list_methods = {
                "append": PyType.callable_([elem_type], PyType.none()),
                "extend": PyType.callable_([PyType.any_()], PyType.none()),
                "insert": PyType.callable_([PyType.int_(), elem_type], PyType.none()),
                "remove": PyType.callable_([elem_type], PyType.none()),
                "pop": PyType.callable_([], elem_type),
                "clear": PyType.callable_([], PyType.none()),
                "index": PyType.callable_([elem_type], PyType.int_()),
                "count": PyType.callable_([elem_type], PyType.int_()),
                "sort": PyType.callable_([], PyType.none()),
                "reverse": PyType.callable_([], PyType.none()),
                "copy": PyType.callable_([], obj),
            }

            if attr_name in list_methods:
                return list_methods[attr_name]

        if obj.kind in {TypeKind.DICT, TypeKind.DEFAULTDICT}:
            key_type = obj.get_key_type()

            val_type = obj.get_value_type()

            dict_methods = {
                "keys": PyType.callable_([], PyType.instance("dict_keys")),
                "values": PyType.callable_([], PyType.instance("dict_values")),
                "items": PyType.callable_([], PyType.instance("dict_items")),
                "get": PyType.callable_([key_type], PyType.optional_(val_type)),
                "pop": PyType.callable_([key_type], val_type),
                "popitem": PyType.callable_([], PyType.tuple_(key_type, val_type)),
                "setdefault": PyType.callable_([key_type, val_type], val_type),
                "update": PyType.callable_([PyType.any_()], PyType.none()),
                "clear": PyType.callable_([], PyType.none()),
                "copy": PyType.callable_([], obj),
                "fromkeys": PyType.callable_([PyType.any_()], obj),
            }

            if attr_name in dict_methods:
                return dict_methods[attr_name]

        if obj.kind == TypeKind.SET:
            elem_type = obj.get_element_type()

            set_methods = {
                "add": PyType.callable_([elem_type], PyType.none()),
                "remove": PyType.callable_([elem_type], PyType.none()),
                "discard": PyType.callable_([elem_type], PyType.none()),
                "pop": PyType.callable_([], elem_type),
                "clear": PyType.callable_([], PyType.none()),
                "copy": PyType.callable_([], obj),
                "update": PyType.callable_([PyType.any_()], PyType.none()),
                "union": PyType.callable_([PyType.any_()], obj),
                "intersection": PyType.callable_([PyType.any_()], obj),
                "difference": PyType.callable_([PyType.any_()], obj),
                "symmetric_difference": PyType.callable_([PyType.any_()], obj),
                "issubset": PyType.callable_([PyType.any_()], PyType.bool_()),
                "issuperset": PyType.callable_([PyType.any_()], PyType.bool_()),
                "isdisjoint": PyType.callable_([PyType.any_()], PyType.bool_()),
            }

            if attr_name in set_methods:
                return set_methods[attr_name]

        if obj.kind == TypeKind.DEQUE:
            elem_type = obj.get_element_type()

            deque_methods = {
                "append": PyType.callable_([elem_type], PyType.none()),
                "appendleft": PyType.callable_([elem_type], PyType.none()),
                "pop": PyType.callable_([], elem_type),
                "popleft": PyType.callable_([], elem_type),
                "extend": PyType.callable_([PyType.any_()], PyType.none()),
                "extendleft": PyType.callable_([PyType.any_()], PyType.none()),
                "clear": PyType.callable_([], PyType.none()),
                "copy": PyType.callable_([], obj),
                "rotate": PyType.callable_([PyType.int_()], PyType.none()),
                "count": PyType.callable_([elem_type], PyType.int_()),
                "index": PyType.callable_([elem_type], PyType.int_()),
                "insert": PyType.callable_([PyType.int_(), elem_type], PyType.none()),
                "remove": PyType.callable_([elem_type], PyType.none()),
                "reverse": PyType.callable_([], PyType.none()),
                "maxlen": PyType.optional_(PyType.int_()),
            }

            if attr_name in deque_methods:
                return deque_methods[attr_name]

        if self.stub_resolver and obj.class_name:
            try:
                module = getattr(obj, "module", "builtins")

                stub_type = self.stub_resolver.resolve_attribute(module, obj.class_name, attr_name)

                if stub_type is not None and hasattr(stub_type, "to_pytype"):
                    return stub_type.to_pytype()

            except Exception:
                pass

        return PyType.any_()

    def infer_call_result(
        self,
        callee: PyType,
        args: list[PyType],
        kwargs: dict[str, PyType],
    ) -> PyType:
        """Infer result type of a function call."""

        if callee.kind == TypeKind.CALLABLE:
            return callee.get_return_type()

        if callee.kind == TypeKind.CLASS:
            class_name = callee.class_name or callee.name

            if class_name == "int":
                return PyType.int_()

            if class_name == "str":
                return PyType.str_()

            if class_name == "float":
                return PyType.float_()

            if class_name == "bool":
                return PyType.bool_()

            if class_name == "list":
                return PyType.list_()

            if class_name == "dict":
                return PyType.dict_()

            if class_name == "set":
                return PyType.set_()

            if class_name == "tuple":
                return PyType.tuple_()

            if class_name == "bytes":
                return PyType.bytes_()

            return PyType.instance(class_name)

        return PyType.any_()

    def narrow_type_for_isinstance(
        self,
        var_type: PyType,
        check_type: PyType,
        positive: bool = True,
    ) -> PyType:
        """
        Narrow a type based on isinstance() check.
        Args:
            var_type: Current type of the variable
            check_type: Type being checked against
            positive: True if check passed, False if failed
        Returns:
            Narrowed type
        """

        if positive:
            return var_type.meet(check_type)

        else:
            if var_type.kind == TypeKind.UNION:
                remaining = [m for m in var_type.union_members if not m.is_subtype_of(check_type)]

                if not remaining:
                    return PyType.bottom()

                if len(remaining) == 1:
                    return remaining[0]

                return PyType.union_(*remaining)

            if var_type.is_subtype_of(check_type):
                return PyType.bottom()

            return var_type

    def narrow_type_for_none_check(
        self,
        var_type: PyType,
        is_none: bool,
    ) -> PyType:
        """
        Narrow type based on None check.
        Args:
            var_type: Current type
            is_none: True if "x is None" passed, False if "x is not None" passed
        Returns:
            Narrowed type
        """

        if is_none:
            return PyType.none()

        else:
            return var_type.without_none()

    def narrow_type_for_truthiness(
        self,
        var_type: PyType,
        is_truthy: bool,
    ) -> PyType:
        """
        Narrow type based on truthiness check (if x:).
        Args:
            var_type: Current type
            is_truthy: True if truthy branch, False if falsy branch
        Returns:
            Narrowed type
        """

        if is_truthy:
            narrowed = var_type.without_none()

            return narrowed

        else:
            return var_type
