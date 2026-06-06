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

"""TypeValueInferenceMixin implementation for type inference."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeGuard

from pysymex.analysis.static.types.kinds import PyType, TypeKind
from pysymex.logger import get_logger
from pysymex.typing import (
    is_dict_of_objects,
    is_list_of_objects,
    is_set_of_objects,
    is_tuple_of_objects,
)

logger = get_logger(__name__)


class _FunctionSignatureInference(Protocol):
    def infer_function_signature(
        self, func: Callable[..., object]
    ) -> tuple[list[PyType], PyType]: ...


def _has_function_signature_inference(value: object) -> TypeGuard[_FunctionSignatureInference]:
    return callable(getattr(value, "infer_function_signature", None))


def _is_frozenset_of_objects(value: object) -> TypeGuard[frozenset[object]]:
    return isinstance(value, frozenset)


class TypeValueInferenceMixin:
    def infer_from_value(self, value: object) -> PyType:
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
        if is_list_of_objects(value):
            if not value:
                return PyType.list_()
            elem_types = [self.infer_from_value(e) for e in value[:5]]
            combined = elem_types[0]
            for t in elem_types[1:]:
                combined = combined.join(t)
            return PyType.list_(combined)
        if is_dict_of_objects(value):
            if not value:
                return PyType.dict_()
            keys: list[object] = list(value.keys())[:5]
            vals: list[object] = list(value.values())[:5]
            key_types = [self.infer_from_value(k) for k in keys]
            val_types = [self.infer_from_value(v) for v in vals]
            key_type = key_types[0]
            val_type = val_types[0]
            for t in key_types[1:]:
                key_type = key_type.join(t)
            for t in val_types[1:]:
                val_type = val_type.join(t)
            return PyType.dict_(key_type, val_type)
        if is_set_of_objects(value):
            if not value:
                return PyType.set_()
            elem_types = [self.infer_from_value(e) for e in list(value)[:5]]
            combined = elem_types[0]
            for t in elem_types[1:]:
                combined = combined.join(t)
            return PyType.set_(combined)
        if is_tuple_of_objects(value):
            elem_types = tuple(self.infer_from_value(e) for e in value)
            return PyType.tuple_(*elem_types)
        if _is_frozenset_of_objects(value):
            if not value:
                return PyType(kind=TypeKind.FROZENSET, name="frozenset")
            elem_types = [self.infer_from_value(e) for e in list(value)[:5]]
            combined = elem_types[0]
            for t in elem_types[1:]:
                combined = combined.join(t)
            return PyType(
                kind=TypeKind.FROZENSET,
                name="frozenset",
                params=(combined,),
            )
        if callable(value):
            if not _has_function_signature_inference(self):
                raise AttributeError(
                    f"{type(self).__name__!s} has no infer_function_signature method"
                )
            try:
                param_types, return_type = self.infer_function_signature(value)
                return PyType.callable_(param_types, return_type)
            except (TypeError, ValueError):
                logger.debug("Failed to infer callable signature from value", exc_info=True)
                return PyType(kind=TypeKind.CALLABLE, name="Callable")
        return PyType.instance(type(value).__name__)


__all__ = ["TypeValueInferenceMixin"]
