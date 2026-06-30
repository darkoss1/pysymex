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

"""Consolidated context-manager exception suppression policy."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Final, Protocol

from pysymex._internal.core.cache.code.instructions import get_instructions

if TYPE_CHECKING:
    import dis

_EXCEPTION_TYPES: Final[dict[str, type[BaseException]]] = {
    "ZeroDivisionError": ZeroDivisionError,
    "TypeError": TypeError,
    "ValueError": ValueError,
    "AttributeError": AttributeError,
    "IndexError": IndexError,
    "KeyError": KeyError,
}

_SIDE_EFFECT_FREE_PREFIX: Final[frozenset[str]] = frozenset(
    (
        "RESUME",
        "NOP",
        "COPY_FREE_VARS",
        "LOAD_FAST",
        "LOAD_FAST_LOAD_FAST",
        "BUILD_TUPLE",
        "STORE_FAST",
        "POP_TOP",
    ),
)


class GlobalLookup(Protocol):
    """Protocol for looking up objects in the global namespace."""

    def get(self, key: str) -> object | None:
        """Return a global name value when present."""
        ...


class SuppressionManagerPolicy:
    """Policy for checking exception suppression by context managers."""

    @classmethod
    def known_suppresses(
        cls,
        globals_: GlobalLookup,
        exception_name: str,
        manager_name: str,
        argument_names: tuple[str, ...],
    ) -> bool:
        """Return whether a modeled manager provably suppresses this exception."""
        raised_type = _EXCEPTION_TYPES.get(exception_name)
        if raised_type is None:
            return False
        manager = globals_.get(manager_name)
        if cls._is_contextlib_suppress(manager):
            return cls._contextlib_suppresses(globals_, raised_type, argument_names)
        if argument_names:
            return False
        exit_code = cls._find_exit_code(manager)
        return exit_code is not None and cls._exit_code_suppresses(globals_, exit_code, raised_type)

    @classmethod
    def _is_contextlib_suppress(cls, manager: object) -> bool:
        """Return whether *manager* is ``contextlib.suppress``."""
        return (
            getattr(manager, "__module__", None) == "contextlib"
            and getattr(manager, "__name__", None) == "suppress"
        )

    @classmethod
    def _contextlib_suppresses(
        cls,
        globals_: GlobalLookup,
        raised_type: type[BaseException],
        argument_names: tuple[str, ...],
    ) -> bool:
        """Return whether a ``contextlib.suppress`` call suppresses the raised exception type."""
        for argument_name in argument_names:
            suppressed_type = globals_.get(argument_name)
            if isinstance(suppressed_type, type) and issubclass(suppressed_type, BaseException):
                if issubclass(raised_type, suppressed_type):
                    return True
        return False

    @classmethod
    def _find_exit_code(cls, manager: object) -> types.CodeType | None:
        """Locate the code object corresponding to a modeled manager ``__exit__`` method."""
        if getattr(manager, "_pysymex_plain_class_definition", False) is not True:
            return None
        class_body = cls._code_payload(getattr(manager, "_modeled_object", None))
        if class_body is None:
            return None
        if cls._declares_custom_construction(class_body):
            return None
        return cls._find_plain_class_method(class_body, "__exit__")

    @classmethod
    def _code_payload(cls, value: object) -> types.CodeType | None:
        """Return a code object from modeled plain-class payload metadata."""
        if isinstance(value, types.CodeType):
            return value
        code = getattr(value, "code", None)
        if isinstance(code, types.CodeType):
            return code
        return None

    @classmethod
    def _declares_custom_construction(cls, class_body: types.CodeType) -> bool:
        """Return whether a class body declares a custom ``__init__`` or ``__new__`` method."""
        return any(
            isinstance(value, types.CodeType) and value.co_name in {"__init__", "__new__"}
            for value in class_body.co_consts
        )

    @classmethod
    def _find_plain_class_method(
        cls,
        class_body: types.CodeType,
        name: str,
    ) -> types.CodeType | None:
        """Find the code object stored under *name* in a plain class body."""
        instructions = list(get_instructions(class_body))
        stores = [
            instr
            for instr in instructions
            if instr.opname in {"STORE_NAME", "STORE_GLOBAL"} and instr.argval == name
        ]
        if len(stores) != 1:
            return None
        for index, instr in enumerate(instructions):
            if instr.opname != "LOAD_CONST" or not isinstance(instr.argval, types.CodeType):
                continue
            code = instr.argval
            if code.co_name != name or index + 1 >= len(instructions):
                continue
            if instructions[index + 1].opname != "MAKE_FUNCTION":
                continue
            cursor = index + 2
            while (
                cursor < len(instructions)
                and instructions[cursor].opname == "SET_FUNCTION_ATTRIBUTE"
            ):
                cursor += 1
            if (
                cursor < len(instructions)
                and instructions[cursor].opname in {"STORE_NAME", "STORE_GLOBAL"}
                and instructions[cursor].argval == name
            ):
                return code
        return None

    @classmethod
    def _exit_code_suppresses(
        cls,
        globals_: GlobalLookup,
        exit_code: types.CodeType,
        raised_type: type[BaseException],
    ) -> bool:
        """Return whether a proven-safe ``__exit__`` body suppresses the raised exception."""
        if exit_code.co_argcount < 4:
            return False
        instructions = [
            instr
            for instr in get_instructions(exit_code)
            if instr.opname not in {"CACHE", "EXTENDED_ARG"}
        ]
        if instructions and instructions[-1].opname == "RETURN_CONST":
            return instructions[-1].argval is True and cls._prefix_is_safe(instructions[:-1])
        if len(instructions) >= 2 and instructions[-2].opname == "LOAD_CONST":
            if instructions[-1].opname == "RETURN_VALUE" and instructions[-2].argval is True:
                return cls._prefix_is_safe(instructions[:-2])
        if len(instructions) < 4:
            return False
        load_exc_type, load_checked_type, identity_check, return_value = instructions[-4:]
        if (
            load_exc_type.opname != "LOAD_FAST"
            or load_exc_type.argval != exit_code.co_varnames[1]
            or load_checked_type.opname not in {"LOAD_GLOBAL", "LOAD_NAME"}
            or not isinstance(load_checked_type.argval, str)
            or identity_check.opname != "IS_OP"
            or identity_check.arg != 0
            or return_value.opname != "RETURN_VALUE"
            or not cls._prefix_is_safe(instructions[:-4])
        ):
            return False
        return globals_.get(load_checked_type.argval) is raised_type

    @classmethod
    def _prefix_is_safe(cls, instructions: list[dis.Instruction]) -> bool:
        """Return whether a ``__exit__`` return prefix is side-effect free."""
        return all(instr.opname in _SIDE_EFFECT_FREE_PREFIX for instr in instructions)
