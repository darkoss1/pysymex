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

"""Precision helpers for ``sorted`` over modeled local instances."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import types
from typing import cast

from pysymex.core.cache import get_instructions as cached_get_instructions
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.calls.payload import function_payload
from pysymex.models.objects import SymbolicInstance

from pysymex.typing import StackValue

_ConcreteNumeric = int | float | bool
_IGNORED_METHOD_OPS = frozenset({"CACHE", "COPY_FREE_VARS", "EXTENDED_ARG", "NOP", "RESUME"})


@dataclass(frozen=True, slots=True)
class _AttributeSortSpec:
    """Exact modeled ``__lt__`` shape supported by the sort model."""

    attr_name: str
    descending: bool


def safe_sorted_modeled_instances(
    values: Sequence[StackValue], *, reverse: bool
) -> Sequence[StackValue] | None:
    """Return exactly sorted modeled instances for simple attribute-backed ``__lt__``."""
    instances = [_modeled_instance(value) for value in values]
    if any(instance is None for instance in instances):
        return None
    typed_instances = cast("list[SymbolicInstance]", instances)
    spec = _attribute_sort_spec(typed_instances)
    if spec is None:
        return None
    payloads = _attribute_payloads(typed_instances, spec.attr_name)
    if payloads is None:
        return None
    effective_reverse = reverse ^ spec.descending
    return _sort_values_by_payloads(values, payloads, reverse=effective_reverse)


def _modeled_instance(value: object) -> SymbolicInstance | None:
    """Return the modeled instance payload attached to a symbolic object value."""
    if not isinstance(value, SymbolicValue):
        return None
    modeled = getattr(value, "_modeled_object", None)
    return modeled if isinstance(modeled, SymbolicInstance) else None


def _attribute_sort_spec(instances: Sequence[SymbolicInstance]) -> _AttributeSortSpec | None:
    """Infer a safe attribute sort key from a shared modeled ``__lt__`` method."""
    if not instances:
        return None
    cls = instances[0].cls
    if any(instance.cls is not cls for instance in instances):
        return None
    method = cls.get_method("__lt__")
    if method is None:
        return None
    payload = function_payload(method.func)
    if payload is None:
        return None
    return _lt_attribute_sort_spec(payload.code)


def _lt_attribute_sort_spec(code: types.CodeType) -> _AttributeSortSpec | None:
    """Recognize ``return self.attr < other.attr`` style comparison methods."""
    if code.co_argcount < 2:
        return None
    self_name = code.co_varnames[0]
    other_name = code.co_varnames[1]
    instructions = [
        instr for instr in cached_get_instructions(code) if instr.opname not in _IGNORED_METHOD_OPS
    ]
    if len(instructions) != 6:
        return None
    first_load, first_attr, second_load, second_attr, compare, ret = instructions
    if (
        first_load.opname != "LOAD_FAST"
        or second_load.opname != "LOAD_FAST"
        or first_attr.opname != "LOAD_ATTR"
        or second_attr.opname != "LOAD_ATTR"
        or compare.opname != "COMPARE_OP"
        or ret.opname != "RETURN_VALUE"
    ):
        return None
    if not isinstance(first_attr.argval, str) or first_attr.argval != second_attr.argval:
        return None
    if compare.argval not in {"<", ">"}:
        return None
    first_name = first_load.argval
    second_name = second_load.argval
    if first_name == self_name and second_name == other_name:
        return _AttributeSortSpec(first_attr.argval, descending=compare.argval == ">")
    if first_name == other_name and second_name == self_name:
        return _AttributeSortSpec(first_attr.argval, descending=compare.argval == "<")
    return None


def _attribute_payloads(
    instances: Sequence[SymbolicInstance], attr_name: str
) -> list[object] | None:
    """Return retained concrete attribute payloads from all modeled instances."""
    payloads: list[object] = []
    for instance in instances:
        if attr_name not in instance.attrs:
            return None
        payload = instance.attrs[attr_name]
        if isinstance(payload, SymbolicValue):
            payload = payload.value
        if not isinstance(payload, (int, float, bool, str, bytes)):
            return None
        payloads.append(payload)
    return payloads


def _sort_values_by_payloads(
    values: Sequence[StackValue], payloads: Sequence[object], *, reverse: bool
) -> Sequence[StackValue] | None:
    """Sort values by homogeneous CPython-comparable payloads."""
    if all(isinstance(payload, (int, float, bool)) for payload in payloads):
        numeric_payloads = cast("Sequence[_ConcreteNumeric]", payloads)
        indexes = sorted(
            range(len(values)),
            key=lambda index: numeric_payloads[index],
            reverse=reverse,
        )
        return [values[index] for index in indexes]
    if all(isinstance(payload, str) for payload in payloads):
        str_payloads = cast("Sequence[str]", payloads)
        indexes = sorted(range(len(values)), key=lambda index: str_payloads[index], reverse=reverse)
        return [values[index] for index in indexes]
    if all(isinstance(payload, bytes) for payload in payloads):
        bytes_payloads = cast("Sequence[bytes]", payloads)
        indexes = sorted(
            range(len(values)),
            key=lambda index: bytes_payloads[index],
            reverse=reverse,
        )
        return [values[index] for index in indexes]
    return None


__all__ = ["safe_sorted_modeled_instances"]
