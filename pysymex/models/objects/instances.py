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

"""Symbolic object instances and bound methods."""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from pysymex.models.objects.classes import SymbolicClass
from pysymex.models.objects.types import SymbolicMethod


@dataclass
class SymbolicInstance:
    """A symbolic instance of a class.
    Represents an object with symbolic attribute values.
    """

    cls: SymbolicClass
    instance_id: int
    attrs: dict[str, object] = field(default_factory=lambda: {})
    _z3_id: z3.ArithRef | None = None
    initialized: bool = False
    init_values: dict[str, object] = field(default_factory=dict[str, object])
    _modified_attrs: set[str] = field(default_factory=set[str])
    _accessed_attrs: set[str] = field(default_factory=set[str])

    @property
    def z3_id(self) -> z3.ArithRef:
        """Get Z3 integer representing object identity."""
        if self._z3_id is None:
            self._z3_id = z3.Int(f"obj_{self.instance_id}")
        return self._z3_id

    def get_attr(self, name: str) -> object:
        """Get an attribute value.
        Checks instance attrs first, then class attrs via MRO.
        """
        if name == "__dict__" and self._has_instance_dict():
            return self.attrs
        if name in self.attrs:
            return self.attrs[name]
        class_attr = self.cls.get_attribute(name)
        if class_attr is not None:
            return class_attr.value
        method = self.cls.get_method(name)
        if method is not None:
            return BoundMethod(instance=self, method=method)
        return None

    def get_attribute(self, name: str, bound_instance: object | None = None) -> tuple[object, bool]:
        """Resolve modeled attributes and bind methods for execution."""
        self._accessed_attrs.add(name)
        if name == "__dict__":
            if self._has_instance_dict():
                return self.attrs, True
            return None, False
        if name in self.cls.properties:
            prop = self.cls.properties[name]
            fget = getattr(prop, "fget", None)
            if callable(fget):
                return fget(self), True
        if name in self.attrs:
            return self.attrs[name], True
        class_attr = self.cls.get_attribute(name)
        if class_attr is not None:
            return class_attr.value, True
        method = self.cls.get_method(name)
        if method is not None:
            return method.bind_to_instance(
                bound_instance if bound_instance is not None else self
            ), True
        return None, False

    def set_attr(self, name: str, value: object) -> None:
        """Set an instance attribute."""
        self.set_attribute(name, value)

    def set_attribute(self, name: str, value: object) -> bool:
        """Write an instance attribute subject to properties and slots."""
        self._modified_attrs.add(name)
        if self.cls.named_tuple_fields is not None:
            return False
        if self.cls.is_dataclass and self.cls.dataclass_frozen and self.initialized:
            return False
        if name in self.cls.properties:
            fset = getattr(self.cls.properties[name], "fset", None)
            return callable(fset)
        if self.cls.slots is not None and name not in self.cls.slots:
            return False
        self.attrs[name] = value
        return True

    def has_attr(self, name: str) -> bool:
        """Check if attribute exists."""
        return (
            name in self.attrs
            or self.cls.get_attribute(name) is not None
            or self.cls.get_method(name) is not None
        )

    def del_attr(self, name: str) -> bool:
        """Delete an instance attribute."""
        if name in self.attrs:
            del self.attrs[name]
            return True
        return False

    def delete_attribute(self, name: str) -> bool:
        """Delete an instance attribute through the modeled protocol."""
        self._modified_attrs.add(name)
        if self.cls.named_tuple_fields is not None:
            return False
        if self.cls.is_dataclass and self.cls.dataclass_frozen and self.initialized:
            return False
        if name in self.cls.properties:
            return callable(getattr(self.cls.properties[name], "fdel", None))
        return self.del_attr(name)

    def copy(self) -> SymbolicInstance:
        """Copy modeled state while preserving symbolic object identity."""
        return SymbolicInstance(
            cls=self.cls,
            instance_id=self.instance_id,
            attrs=dict(self.attrs),
            _z3_id=self._z3_id,
            initialized=self.initialized,
            init_values=dict(self.init_values),
            _modified_attrs=set(self._modified_attrs),
            _accessed_attrs=set(self._accessed_attrs),
        )

    @property
    def modified_attrs(self) -> set[str]:
        return self._modified_attrs

    @property
    def accessed_attrs(self) -> set[str]:
        return self._accessed_attrs

    def _has_instance_dict(self) -> bool:
        """Return whether CPython would expose an instance ``__dict__``."""
        return self.cls.slots is None or "__dict__" in self.cls.slots

    def isinstance_of(self, cls: SymbolicClass) -> bool:
        """Check if instance is of a class (including subclasses)."""
        return self.cls.is_subclass_of(cls)


@dataclass
class BoundMethod:
    """A method bound to an instance."""

    instance: SymbolicInstance
    method: SymbolicMethod

    @property
    def is_bound(self) -> bool:
        return True

    def get_call_args(
        self,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> tuple[tuple[object, ...], dict[str, object]]:
        if args and args[0] is self.instance:
            return args, kwargs
        return (self.instance, *args), kwargs

    def __call__(self, *args: object, **kwargs: object) -> object:
        """Call the bound method."""
        if callable(self.method.func):
            return self.method.func(self.instance, *args, **kwargs)
        return None


__all__ = ["BoundMethod", "SymbolicInstance"]
