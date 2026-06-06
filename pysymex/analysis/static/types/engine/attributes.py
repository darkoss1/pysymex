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

"""TypeAttributeInferenceMixin implementation for type inference."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, cast

from pysymex.analysis.static.types.kinds import PyType, TypeKind
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.analysis.static.stubs.resolver import StubBasedTypeResolver

logger = get_logger(__name__)


class _AttributeInferenceHost(Protocol):
    @property
    def stub_resolver(self) -> StubBasedTypeResolver | None: ...


class TypeAttributeInferenceMixin:
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

        host = cast("_AttributeInferenceHost", self)
        if host.stub_resolver and obj.class_name:
            try:
                module = getattr(obj, "module", "builtins")
                resolve_attribute = getattr(host.stub_resolver, "resolve_attribute", None)
                stub_type = (
                    resolve_attribute(module, obj.class_name, attr_name)
                    if callable(resolve_attribute)
                    else None
                )
                to_pytype = getattr(stub_type, "to_pytype", None)
                if callable(to_pytype):
                    return cast("PyType", to_pytype())
            except (AttributeError, KeyError, TypeError):
                logger.debug(
                    "Failed to resolve attribute type from stubs: %s.%s",
                    obj.class_name,
                    attr_name,
                    exc_info=True,
                )
        return PyType.any_()


__all__ = ["TypeAttributeInferenceMixin"]
