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

"""Symbolic class model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pysymex._internal.core.calls.payload import function_payload, method_descriptor_payload
from pysymex._internal.core.classes.types import (
    InitParameter,
    MethodType,
    SymbolicAttribute,
    SymbolicMethod,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    import z3


def _empty_bases() -> list[SymbolicClass]:
    """Create a typed empty base-class list."""
    return []


def _empty_class_attrs() -> dict[str, SymbolicAttribute]:
    """Create a typed empty class-attribute mapping."""
    return {}


def _empty_instance_attrs() -> dict[str, SymbolicAttribute]:
    """Create a typed empty instance-attribute mapping."""
    return {}


def _empty_methods() -> dict[str, SymbolicMethod]:
    """Create a typed empty method mapping."""
    return {}


def _empty_dataclass_fields() -> dict[str, tuple[str, object]]:
    """Create a typed empty dataclass-fields mapping."""
    return {}


@dataclass
class SymbolicClass:
    """A symbolic class definition.
    Models Python classes for symbolic execution including:
    - Attributes (class and instance)
    - Methods (instance, class, static)
    - Inheritance (single and multiple)
    - Method Resolution Order (MRO).
    """

    name: str
    bases: list[SymbolicClass] = field(default_factory=_empty_bases)
    class_attrs: dict[str, SymbolicAttribute] = field(default_factory=_empty_class_attrs)
    instance_attrs: dict[str, SymbolicAttribute] = field(default_factory=_empty_instance_attrs)
    methods: dict[str, SymbolicMethod] = field(default_factory=_empty_methods)
    abstract_methods: set[str] = field(default_factory=set[str])
    metaclass: SymbolicClass | None = None
    module: str = "__main__"
    init_params: list[InitParameter] = field(default_factory=list[InitParameter])
    slots: tuple[str, ...] | None = None
    named_tuple_fields: tuple[str, ...] | None = None
    literal_enum_values: tuple[int, ...] | None = None
    is_dataclass: bool = False
    dataclass_frozen: bool = False
    dataclass_fields: dict[str, tuple[str, object]] = field(default_factory=_empty_dataclass_fields)
    properties: dict[str, object] = field(default_factory=dict[str, object])
    class_vars: dict[str, object] = field(default_factory=dict[str, object])
    _pysymex_bases_complete: bool = True
    _pysymex_trusted_cached_property: bool = False
    _pysymex_declared_descriptors: Mapping[str, object] | None = None
    _mro: list[SymbolicClass] | None = None

    def __post_init__(self) -> None:
        self._compute_mro()

    def set_bases_complete(self, bases_complete: bool) -> None:
        """Record whether modeled class bases were completely resolved."""
        self._pysymex_bases_complete = bases_complete

    def mark_trusted_cached_property(self) -> None:
        """Mark this class as allowing trusted cached-property modeling."""
        self._pysymex_trusted_cached_property = True

    @property
    def trusted_cached_property(self) -> bool:
        """Return whether trusted cached-property modeling is enabled."""
        return self._pysymex_trusted_cached_property

    @property
    def declared_descriptors(self) -> Mapping[str, object] | None:
        """Return retained declared descriptor bindings."""
        return self._pysymex_declared_descriptors

    def set_declared_descriptors(self, descriptors: Mapping[str, object]) -> None:
        """Replace retained declared descriptor bindings."""
        self._pysymex_declared_descriptors = descriptors

    def _compute_mro(self) -> None:
        """Compute Method Resolution Order using C3 linearization."""
        if not self.bases:
            self._mro = [self]
            return

        def merge(seqs: list[list[SymbolicClass]]) -> list[SymbolicClass]:
            result: list[SymbolicClass] = []
            tail_counts: dict[int, int] = {}
            for s in seqs:
                for i in range(1, len(s)):
                    item_id = id(s[i])
                    tail_counts[item_id] = tail_counts.get(item_id, 0) + 1

            while True:
                seqs = [s for s in seqs if s]
                if not seqs:
                    return result
                for seq in seqs:
                    candidate = seq[0]
                    if not tail_counts.get(id(candidate), 0):
                        result.append(candidate)
                        for s in seqs:
                            if s and s[0] is candidate:
                                s.pop(0)
                                if s:
                                    tail_counts[id(s[0])] -= 1
                        break
                else:
                    msg = "Cannot create MRO"
                    raise TypeError(msg)

        base_mros = [list(base.mro) for base in self.bases]
        self._mro = [self, *merge([*base_mros, list(self.bases)])]

    @property
    def mro(self) -> list[SymbolicClass]:
        """Get Method Resolution Order."""
        if self._mro is None:
            self._compute_mro()
        return self._mro or [self]

    def get_method(self, name: str) -> SymbolicMethod | None:
        """Get method by name, following MRO."""
        for cls in self.mro:
            if name in cls.methods:
                return cls.methods[name]
        return None

    def get_attribute(self, name: str) -> SymbolicAttribute | None:
        """Get class attribute by name, following MRO."""
        for cls in self.mro:
            if name in cls.class_attrs:
                return cls.class_attrs[name]
        return None

    def has_method(self, name: str) -> bool:
        """Check if class has a method (including inherited)."""
        return self.get_method(name) is not None

    def is_subclass_of(self, other: SymbolicClass) -> bool:
        """Check if this class is a subclass of other."""
        return other in self.mro

    @property
    def is_abstract(self) -> bool:
        """Return whether unresolved abstract methods block instantiation."""
        return bool(self.unresolved_abstract_methods)

    @property
    def unresolved_abstract_methods(self) -> set[str]:
        """Return abstract methods not implemented by this class hierarchy."""
        unresolved: set[str] = set()
        for cls in reversed(self.mro):
            unresolved.difference_update(cls.methods)
            unresolved.update(cls.abstract_methods)
        return unresolved

    def abstract_instantiation_message(self) -> str:
        """Return the deterministic CPython-shaped abstract instantiation error."""
        missing = "', '".join(sorted(self.unresolved_abstract_methods))
        return (
            f"Can't instantiate abstract class {self.name} without an implementation "
            f"for abstract method '{missing}'"
        )

    def add_method(
        self,
        name: str,
        func: object = None,
        method_type: MethodType = MethodType.INSTANCE,
        parameters: list[str] | None = None,
        return_type: str | None = None,
        is_abstract: bool = False,
        preconditions: list[z3.BoolRef] | None = None,
        postconditions: list[z3.BoolRef] | None = None,
    ) -> None:
        """Add a method to the class."""
        self.methods[name] = SymbolicMethod(
            name=name,
            func=func,
            method_type=method_type,
            parameters=parameters or [],
            return_type=return_type,
            is_abstract=is_abstract,
            preconditions=preconditions or [],
            postconditions=postconditions or [],
        )
        if is_abstract or method_type == MethodType.ABSTRACT:
            self.abstract_methods.add(name)

    def lookup_method(self, name: str) -> SymbolicMethod | None:
        """Look up a modeled method through the class MRO."""
        return self.get_method(name)

    def add_property(
        self,
        name: str,
        fget: Callable[..., object] | None = None,
        fset: Callable[..., object] | None = None,
        fdel: Callable[..., object] | None = None,
        getter_code: object | None = None,
        setter_code: object | None = None,
        deleter_code: object | None = None,
        getter_func: Callable[..., object] | None = None,
        setter_func: Callable[..., object] | None = None,
        deleter_func: Callable[..., object] | None = None,
    ) -> None:
        """Register a modeled property descriptor on this class."""
        from pysymex._internal.core.classes.descriptors import SymbolicProperty

        self.properties[name] = SymbolicProperty(
            fget=fget,
            fset=fset,
            fdel=fdel,
            name=name,
            getter_code=getter_code,
            setter_code=setter_code,
            deleter_code=deleter_code,
            getter_func=getter_func,
            setter_func=setter_func,
            deleter_func=deleter_func,
        )

    def add_class_attr(
        self,
        name: str,
        value: object,
        is_readonly: bool = False,
        type_hint: str | None = None,
    ) -> None:
        """Add a class attribute."""
        modeled_value = getattr(value, "_modeled_object", value)
        descriptor_payload = method_descriptor_payload(modeled_value)
        if descriptor_payload is not None:
            payload = descriptor_payload.payload
            method_type = (
                MethodType.CLASS if descriptor_payload.kind == "class" else MethodType.STATIC
            )
            self.add_method(
                name,
                payload,
                method_type=method_type,
                parameters=list(payload.code.co_varnames[: payload.code.co_argcount]),
            )
            self.class_vars.pop(name, None)
            self.class_attrs.pop(name, None)
            return
        payload = function_payload(modeled_value)
        if payload is not None:
            self.add_method(
                name,
                payload,
                method_type=MethodType.INSTANCE,
                parameters=list(payload.code.co_varnames[: payload.code.co_argcount]),
            )
            self.class_vars.pop(name, None)
            self.class_attrs.pop(name, None)
            return
        self.class_attrs[name] = SymbolicAttribute(
            name=name,
            value=value,
            is_class_attr=True,
            is_readonly=is_readonly,
            type_hint=type_hint,
        )
        self.class_vars[name] = value

    def set_init_params(self, params: list[InitParameter]) -> None:
        """Set __init__ parameter info."""
        self.init_params = params
