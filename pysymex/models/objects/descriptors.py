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

"""Symbolic descriptor models."""

from __future__ import annotations

from collections.abc import Callable

from pysymex.models.objects.classes import SymbolicClass
from pysymex.models.objects.instances import SymbolicInstance


class SymbolicDescriptor:
    """Base class for symbolic descriptors (property, classmethod, etc.)."""

    def __get__(self, instance: SymbolicInstance | None, owner: SymbolicClass) -> object:
        if instance is None:
            return self
        raise AttributeError("unreadable attribute")

    def __set__(self, instance: SymbolicInstance, value: object) -> None:
        """Set."""
        raise AttributeError("can't set attribute")

    def __delete__(self, instance: SymbolicInstance) -> None:
        """Delete."""
        raise AttributeError("can't delete attribute")


class SymbolicProperty(SymbolicDescriptor):
    """Symbolic property descriptor."""

    def __init__(
        self,
        fget: Callable[..., object] | None = None,
        fset: Callable[..., object] | None = None,
        fdel: Callable[..., object] | None = None,
        doc: str | None = None,
        name: str = "",
        getter_code: object | None = None,
        setter_code: object | None = None,
        deleter_code: object | None = None,
        getter_func: Callable[..., object] | None = None,
        setter_func: Callable[..., object] | None = None,
        deleter_func: Callable[..., object] | None = None,
    ) -> None:
        """Initialize a new SymbolicProperty instance."""
        self.fget: Callable[..., object] | None = fget
        self.fset: Callable[..., object] | None = fset
        self.fdel: Callable[..., object] | None = fdel
        self.__doc__ = doc
        self.name = name
        self.getter_code = getter_code
        self.setter_code = setter_code
        self.deleter_code = deleter_code
        self.getter_func = getter_func
        self.setter_func = setter_func
        self.deleter_func = deleter_func

    def __get__(self, instance: SymbolicInstance | None, owner: SymbolicClass) -> object:
        """Get."""
        if instance is None:
            return self
        if self.fget is None:
            raise AttributeError("unreadable attribute")
        return self.fget(instance)

    def __set__(self, instance: SymbolicInstance, value: object) -> None:
        """Set."""
        if self.fset is None:
            raise AttributeError("can't set attribute")
        self.fset(instance, value)

    def __delete__(self, instance: SymbolicInstance) -> None:
        """Delete."""
        if self.fdel is None:
            raise AttributeError("can't delete attribute")
        self.fdel(instance)


__all__ = ["SymbolicDescriptor", "SymbolicProperty"]
