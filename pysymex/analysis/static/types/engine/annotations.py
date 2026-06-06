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

"""TypeAnnotationInferenceMixin implementation for type inference."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from types import UnionType
from typing import (
    TYPE_CHECKING,
    Protocol,
    TypeGuard,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)

from pysymex.analysis.static.types.engine.stubs import convert_stub_to_pytype
from pysymex.analysis.static.types.kinds import PyType, TypeKind
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.analysis.static.stubs.resolver import StubBasedTypeResolver

logger = get_logger(__name__)


class _AnnotationInferenceHost(Protocol):
    function_signatures: dict[str, tuple[list[PyType], PyType]]

    @property
    def stub_resolver(self) -> StubBasedTypeResolver | None: ...

    def infer_from_value(self, value: object) -> PyType: ...


class _FunctionStubLike(Protocol):
    params: dict[str, object]
    return_type: object | None


def _is_function_stub_like(value: object) -> TypeGuard[_FunctionStubLike]:
    params = getattr(value, "params", None)
    return isinstance(params, dict) and hasattr(value, "return_type")


class TypeAnnotationInferenceMixin:
    function_signatures: dict[str, tuple[list[PyType], PyType]]

    def infer_from_annotation(self, annotation: object) -> PyType:
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
        origin = get_origin(annotation)
        args = get_args(annotation)
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
        if origin in {Union, UnionType}:
            if len(args) == 2 and type(None) in args:
                inner = args[0] if args[1] is type(None) else args[1]
                return PyType.optional_(self.infer_from_annotation(inner))
            member_types = [self.infer_from_annotation(a) for a in args]
            return PyType.union_(*member_types)
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
        if annotation.startswith(("dict[", "Dict[")):
            inner = annotation[5:-1]
            parts = inner.split(",", 1)
            if len(parts) == 2:
                key_type = self._parse_string_annotation(parts[0].strip())
                val_type = self._parse_string_annotation(parts[1].strip())
                return PyType.dict_(key_type, val_type)
        if annotation.startswith(("set[", "Set[")):
            inner = annotation[4:-1]
            return PyType.set_(self._parse_string_annotation(inner))
        if annotation.startswith(("tuple[", "Tuple[")):
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

    def infer_function_signature(self, func: Callable[..., object]) -> tuple[list[PyType], PyType]:
        """Infer parameter and return types for a function."""
        host = cast("_AnnotationInferenceHost", self)
        func_name = getattr(func, "__qualname__", str(func))
        if func_name in host.function_signatures:
            return host.function_signatures[func_name]
        try:
            hints = get_type_hints(func)
        except (TypeError, ValueError, NameError):
            logger.debug("Failed to resolve function type hints for %s", func_name, exc_info=True)
            hints = {}

        stub_func = None
        if not hints and host.stub_resolver:
            module = getattr(func, "__module__", None)
            name = getattr(func, "__name__", None)
            if module and name:
                try:
                    repository = getattr(host.stub_resolver, "repository", None)
                    get_function_type = getattr(repository, "get_function_type", None)
                    if callable(get_function_type):
                        stub_func = get_function_type(module, name)
                except (AttributeError, KeyError, TypeError):
                    logger.debug(
                        "Failed to resolve stub signature for %s", func_name, exc_info=True
                    )
                    pass
        try:
            sig = inspect.signature(func)
        except (TypeError, ValueError):
            logger.debug("No inspectable function signature for %s", func_name, exc_info=True)
            if _is_function_stub_like(stub_func):
                param_types = [
                    convert_stub_to_pytype(param_type) for param_type in stub_func.params.values()
                ]
                return_type = (
                    convert_stub_to_pytype(stub_func.return_type)
                    if stub_func.return_type is not None
                    else PyType.any_()
                )
            else:
                param_types = []
                return_type = PyType.any_()
            host.function_signatures[func_name] = (param_types, return_type)
            return param_types, return_type

        param_types: list[PyType] = []
        for param_name, param in sig.parameters.items():
            if param_name in hints:
                param_types.append(self.infer_from_annotation(hints[param_name]))
            elif param.default is not inspect.Parameter.empty:
                param_types.append(host.infer_from_value(param.default))
            elif _is_function_stub_like(stub_func):
                if param_name in stub_func.params:
                    param_types.append(convert_stub_to_pytype(stub_func.params[param_name]))
                else:
                    param_types.append(PyType.any_())
            else:
                param_types.append(PyType.any_())
        return_type = self.infer_from_annotation(hints.get("return"))
        if (
            return_type.kind == TypeKind.ANY
            and _is_function_stub_like(stub_func)
            and stub_func.return_type is not None
        ):
            return_type = convert_stub_to_pytype(stub_func.return_type)
        host.function_signatures[func_name] = (param_types, return_type)
        return param_types, return_type


__all__ = ["TypeAnnotationInferenceMixin"]
