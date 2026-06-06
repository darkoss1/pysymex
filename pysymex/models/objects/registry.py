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

"""Symbolic class registry and type checks."""

from __future__ import annotations

import z3
from typing import TypeGuard

from pysymex.core.cache.control import register_process_cache_clearer
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.logger import get_logger
from pysymex.models.objects.classes import SymbolicClass
from pysymex.models.objects.instances import SymbolicInstance
from pysymex.models.objects.types import InitParameter


def _is_object_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    return isinstance(value, tuple)


def _object_tuple(value: object) -> tuple[object, ...]:
    if not _is_object_tuple(value):
        return ()
    items: list[object] = []
    for index in range(len(value)):
        item: object = value[index]
        items.append(item)
    return tuple(items)


def _string_tuple(value: object) -> tuple[str, ...]:
    return tuple(str(item) for item in _object_tuple(value))


def extract_init_params(code_obj: object) -> list[InitParameter]:
    if not hasattr(code_obj, "co_varnames"):
        return []
    params: list[InitParameter] = []
    arg_count_obj = getattr(code_obj, "co_argcount", 0)
    arg_count = arg_count_obj if isinstance(arg_count_obj, int) else 0
    varnames = _string_tuple(getattr(code_obj, "co_varnames", ()))
    defaults = _object_tuple(getattr(code_obj, "co_defaults", ()))
    default_offset = arg_count - len(defaults)
    for i, name in enumerate(varnames[:arg_count]):
        is_self = i == 0 and name in ("self", "cls")
        has_default = i >= default_offset
        default = defaults[i - default_offset] if has_default else None
        params.append(
            InitParameter(
                name=str(name),
                is_self=is_self,
                has_default=has_default,
                default=default,
            )
        )
    return params


_BUILTIN_NAMES = ("int", "str", "float", "bool", "list", "dict", "set", "tuple")
logger = get_logger(__name__)


class ClassRegistry:
    """Registry of symbolic class definitions.
    Tracks all classes seen during analysis for type hierarchy
    and instanceof checks.
    """

    def __init__(self) -> None:
        """Initialize a new ClassRegistry instance."""
        self._classes: dict[str, SymbolicClass] = {}
        self._builtin_classes: dict[str, SymbolicClass] = {}
        self._next_instance_id: int = 0
        self._by_code: dict[int, SymbolicClass] = {}
        self._by_code_object: dict[int, tuple[object, SymbolicClass]] = {}
        self._init_builtins()

    def _init_builtins(self) -> None:
        """Initialize symbolic versions of builtin classes."""
        obj_cls = SymbolicClass(name="object", module="builtins")
        obj_cls.add_method("__init__")
        obj_cls.add_method("__str__")
        obj_cls.add_method("__repr__")
        obj_cls.add_method("__eq__")
        obj_cls.add_method("__hash__")
        self._builtin_classes["object"] = obj_cls
        type_cls = SymbolicClass(name="type", bases=[obj_cls], module="builtins")
        self._builtin_classes["type"] = type_cls
        exc_cls = SymbolicClass(name="Exception", bases=[obj_cls], module="builtins")
        self._builtin_classes["Exception"] = exc_cls
        for name in _BUILTIN_NAMES:
            cls = SymbolicClass(name=name, bases=[obj_cls], module="builtins")
            self._builtin_classes[name] = cls

    def register_class(self, cls: SymbolicClass) -> SymbolicClass:
        """Register a class definition."""
        full_name = f"{cls.module}.{cls.name}"
        self._classes[full_name] = cls
        if logger.state.trace_enabled:
            logger.trace("registered symbolic class: %s", full_name)
        return cls

    def get_class(self, name: str, module: str = "__main__") -> SymbolicClass | None:
        """Get a class by name."""
        full_name = f"{module}.{name}"
        if full_name in self._classes:
            return self._classes[full_name]
        if name in self._builtin_classes:
            return self._builtin_classes[name]
        if logger.state.trace_enabled:
            logger.trace("no symbolic class for %s.%s", module, name)
        return None

    def create_instance(
        self,
        cls: SymbolicClass,
        init_attrs: dict[str, object] | None = None,
    ) -> SymbolicInstance:
        """Create a new instance of a class."""
        instance_id = self._next_instance_id
        self._next_instance_id += 1
        instance = SymbolicInstance(
            cls=cls,
            instance_id=instance_id,
            attrs=init_attrs or {},
        )
        if logger.state.trace_enabled:
            logger.trace(
                "created symbolic instance id=%d class=%s.%s",
                instance_id,
                cls.module,
                cls.name,
            )
        return instance

    def instantiate(
        self,
        cls: SymbolicClass,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
        pc: int = 0,
    ) -> SymbolicInstance:
        """Create and initialize an instance from modeled constructor parameters."""
        if cls.is_abstract:
            raise TypeError(cls.abstract_instantiation_message())
        kwargs = kwargs or {}
        init_values: dict[str, object] = {}
        positional_index = 0
        for param in cls.init_params:
            if param.is_self:
                continue
            if param.name in kwargs:
                value = kwargs[param.name]
            elif positional_index < len(args):
                value = args[positional_index]
                positional_index += 1
            elif param.default_factory is not None:
                value = param.default_factory()
            elif param.has_default:
                value = param.default
            else:
                value = param.to_symbolic(pc)
            init_values[param.name] = value
        instance = self.create_instance(cls, init_values)
        instance.init_values = init_values
        instance.initialized = True
        return instance

    def clear(self) -> None:
        self._classes.clear()
        self._by_code.clear()
        self._by_code_object.clear()
        self._next_instance_id = 0
        self._init_builtins()

    def register_code_object(self, code_obj: object, cls: SymbolicClass) -> None:
        code_id = id(code_obj)
        self._by_code_object[code_id] = (code_obj, cls)
        self._by_code[code_id] = cls

    def get_by_code_object(self, code_obj: object) -> SymbolicClass | None:
        code_id = id(code_obj)
        entry = self._by_code_object.get(code_id)
        if entry is None:
            return None
        registered_code, cls = entry
        if registered_code is code_obj:
            return cls
        self._by_code_object.pop(code_id, None)
        self._by_code.pop(code_id, None)
        return None

    def get_builtin(self, name: str) -> SymbolicClass | None:
        """Get a builtin class."""
        return self._builtin_classes.get(name)


class TypeChecker:
    """Runtime type checking for symbolic execution."""

    def __init__(self, registry: ClassRegistry) -> None:
        """Initialize a new TypeChecker instance."""
        self.registry = registry

    def isinstance_check(
        self,
        value: object,
        target_cls: SymbolicClass,
    ) -> z3.BoolRef:
        """Generate symbolic isinstance check."""
        if isinstance(value, SymbolicInstance):
            return Z3_TRUE if value.isinstance_of(target_cls) else Z3_FALSE
        type_name = type(value).__name__
        builtin = self.registry.get_builtin(type_name)
        if builtin:
            return Z3_TRUE if builtin.is_subclass_of(target_cls) else Z3_FALSE
        return Z3_FALSE

    def issubclass_check(
        self,
        child: SymbolicClass,
        parent: SymbolicClass,
    ) -> z3.BoolRef:
        """Generate symbolic issubclass check."""
        return Z3_TRUE if child.is_subclass_of(parent) else Z3_FALSE

    def type_of(self, value: object) -> SymbolicClass | None:
        """Get the symbolic class of a value."""
        if isinstance(value, SymbolicInstance):
            return value.cls
        type_name = type(value).__name__
        return self.registry.get_builtin(type_name)


class_registry = ClassRegistry()
register_process_cache_clearer("models.object_class_registry", class_registry.clear)

__all__ = ["ClassRegistry", "TypeChecker", "class_registry", "extract_init_params"]
