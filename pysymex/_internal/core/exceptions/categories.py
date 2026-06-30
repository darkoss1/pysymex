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

"""Exception category tables and matching helpers."""

from __future__ import annotations

from enum import Enum, auto


class ExceptionCategory(Enum):
    """Coarse classification tags for modeled exception types.

    Unknown concrete exception classes are assigned ``CUSTOM`` by
    :func:`get_exception_category`.
    """

    RUNTIME = auto()
    TYPE = auto()
    VALUE = auto()
    ARITHMETIC = auto()
    LOOKUP = auto()
    ATTRIBUTE = auto()
    NAME = auto()
    IO = auto()
    MEMORY = auto()
    ASSERTION = auto()
    STOP_ITERATION = auto()
    CUSTOM = auto()


EXCEPTION_CATEGORIES: dict[type[BaseException], ExceptionCategory] = {
    RuntimeError: ExceptionCategory.RUNTIME,
    TypeError: ExceptionCategory.TYPE,
    ValueError: ExceptionCategory.VALUE,
    KeyError: ExceptionCategory.LOOKUP,
    IndexError: ExceptionCategory.LOOKUP,
    AttributeError: ExceptionCategory.ATTRIBUTE,
    NameError: ExceptionCategory.NAME,
    UnboundLocalError: ExceptionCategory.NAME,
    ZeroDivisionError: ExceptionCategory.ARITHMETIC,
    OverflowError: ExceptionCategory.ARITHMETIC,
    ArithmeticError: ExceptionCategory.ARITHMETIC,
    IOError: ExceptionCategory.IO,
    FileNotFoundError: ExceptionCategory.IO,
    MemoryError: ExceptionCategory.MEMORY,
    AssertionError: ExceptionCategory.ASSERTION,
    StopIteration: ExceptionCategory.STOP_ITERATION,
}


def get_exception_category(exc_type: type[BaseException]) -> ExceptionCategory:
    """Return the nearest registered category from ``exc_type``'s MRO."""
    if exc_type in EXCEPTION_CATEGORIES:
        return EXCEPTION_CATEGORIES[exc_type]
    for base in exc_type.__mro__:
        if base in EXCEPTION_CATEGORIES:
            return EXCEPTION_CATEGORIES[base]
    return ExceptionCategory.CUSTOM
