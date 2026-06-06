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

"""Proof-oriented exception suppression checks for context managers."""

from __future__ import annotations

import dis
import types
from typing import Protocol

from pysymex.core.cache.code_objects import get_instructions as cached_get_instructions


class _GlobalLookup(Protocol):
    """Protocol for looking up objects in the global namespace."""

    def get(self, key: str) -> object | None:
        """Look up a name in the global namespace.

        Args:
            key (str): The name to look up.

        Returns:
            object | None: The retrieved object if present, otherwise None.
        """
        ...


_EXCEPTION_TYPES: dict[str, type[BaseException]] = {
    "ZeroDivisionError": ZeroDivisionError,
    "TypeError": TypeError,
    "ValueError": ValueError,
    "AttributeError": AttributeError,
    "IndexError": IndexError,
    "KeyError": KeyError,
}
_SIDE_EFFECT_FREE_PREFIX = frozenset(
    {
        "RESUME",
        "NOP",
        "COPY_FREE_VARS",
        "LOAD_FAST",
        "LOAD_FAST_LOAD_FAST",
        "BUILD_TUPLE",
        "STORE_FAST",
        "POP_TOP",
    }
)


def known_with_manager_suppresses(
    globals_: _GlobalLookup,
    exception_name: str,
    manager_name: str,
    argument_names: tuple[str, ...],
) -> bool:
    """Return whether a modeled manager provably suppresses this exception."""
    raised_type = _EXCEPTION_TYPES.get(exception_name)
    if raised_type is None:
        return False
    manager = globals_.get(manager_name)
    if _is_contextlib_suppress(manager):
        return _contextlib_suppresses(globals_, raised_type, argument_names)
    if argument_names:
        return False
    exit_code = _find_exit_code(manager)
    return exit_code is not None and _exit_code_suppresses(globals_, exit_code, raised_type)


def _is_contextlib_suppress(manager: object) -> bool:
    """Check if a manager object is `contextlib.suppress`.

    Args:
        manager (object): The context manager object.

    Returns:
        bool: True if it is `contextlib.suppress`, False otherwise.
    """
    return (
        getattr(manager, "__module__", None) == "contextlib"
        and getattr(manager, "__name__", None) == "suppress"
    )


def _contextlib_suppresses(
    globals_: _GlobalLookup,
    raised_type: type[BaseException],
    argument_names: tuple[str, ...],
) -> bool:
    """Determine if a `contextlib.suppress` call suppresses the raised exception type.

    Args:
        globals_ (_GlobalLookup): The global namespace lookup helper.
        raised_type (type[BaseException]): The raised exception type.
        argument_names (tuple[str, ...]): The names of arguments passed to suppress.

    Returns:
        bool: True if the exception type is suppressed, False otherwise.
    """
    for argument_name in argument_names:
        suppressed_type = globals_.get(argument_name)
        if isinstance(suppressed_type, type) and issubclass(suppressed_type, BaseException):
            if issubclass(raised_type, suppressed_type):
                return True
    return False


def _find_exit_code(manager: object) -> types.CodeType | None:
    """Locate the code object corresponding to the `__exit__` method of a context manager.

    Args:
        manager (object): The context manager object.

    Returns:
        types.CodeType | None: The `__exit__` code object if found, otherwise None.
    """
    if getattr(manager, "_pysymex_plain_class_definition", False) is not True:
        return None
    class_body = _code_payload(getattr(manager, "_modeled_object", None))
    if class_body is None:
        return None
    if _declares_custom_construction(class_body):
        return None
    return _find_plain_class_method(class_body, "__exit__")


def _code_payload(value: object) -> types.CodeType | None:
    """Return a code object from modeled plain-class payload metadata."""
    if isinstance(value, types.CodeType):
        return value
    code = getattr(value, "code", None)
    if isinstance(code, types.CodeType):
        return code
    return None


def _declares_custom_construction(class_body: types.CodeType) -> bool:
    """Determine if the class body declares a custom `__init__` or `__new__` method.

    Args:
        class_body (types.CodeType): The class body code object.

    Returns:
        bool: True if a custom construction method is declared, False otherwise.
    """
    return any(
        isinstance(value, types.CodeType) and value.co_name in {"__init__", "__new__"}
        for value in class_body.co_consts
    )


def _find_plain_class_method(class_body: types.CodeType, name: str) -> types.CodeType | None:
    """Find the code object for a specified method name in a plain class body.

    Args:
        class_body (types.CodeType): The class body code object.
        name (str): The name of the method to search for (e.g. '__exit__').

    Returns:
        types.CodeType | None: The method's code object if found, otherwise None.
    """
    instructions = list(cached_get_instructions(class_body))
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
            cursor < len(instructions) and instructions[cursor].opname == "SET_FUNCTION_ATTRIBUTE"
        ):
            cursor += 1
        if (
            cursor < len(instructions)
            and instructions[cursor].opname in {"STORE_NAME", "STORE_GLOBAL"}
            and instructions[cursor].argval == name
        ):
            return code
    return None


def _exit_code_suppresses(
    globals_: _GlobalLookup,
    exit_code: types.CodeType,
    raised_type: type[BaseException],
) -> bool:
    """Verify if the `__exit__` code object suppresses the raised exception.

    Args:
        globals_ (_GlobalLookup): The global namespace lookup helper.
        exit_code (types.CodeType): The `__exit__` method's code object.
        raised_type (type[BaseException]): The raised exception type.

    Returns:
        bool: True if the code object suppresses the exception (by returning True), False otherwise.
    """
    if exit_code.co_argcount < 4:
        return False
    instructions = [
        instr
        for instr in cached_get_instructions(exit_code)
        if instr.opname not in {"CACHE", "EXTENDED_ARG"}
    ]
    if instructions and instructions[-1].opname == "RETURN_CONST":
        return instructions[-1].argval is True and _prefix_is_safe(instructions[:-1])
    if len(instructions) >= 2 and instructions[-2].opname == "LOAD_CONST":
        if instructions[-1].opname == "RETURN_VALUE" and instructions[-2].argval is True:
            return _prefix_is_safe(instructions[:-2])
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
        or not _prefix_is_safe(instructions[:-4])
    ):
        return False
    return globals_.get(load_checked_type.argval) is raised_type


def _prefix_is_safe(instructions: list[dis.Instruction]) -> bool:
    """Check if all instructions in the given prefix are side-effect free.

    Args:
        instructions (list[dis.Instruction]): The list of instructions to check.

    Returns:
        bool: True if all instructions are side-effect free, False otherwise.
    """
    return all(instr.opname in _SIDE_EFFECT_FREE_PREFIX for instr in instructions)


__all__ = ["known_with_manager_suppresses"]
