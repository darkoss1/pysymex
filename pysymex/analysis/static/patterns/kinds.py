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

"""Pattern-kind enumeration and match-record dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

from pysymex.analysis.static.types import PyType


class PatternKind(Enum):
    """Categories of Python patterns."""

    DICT_GET = auto()
    DICT_SETDEFAULT = auto()
    DICT_POP = auto()
    DEFAULTDICT_ACCESS = auto()
    COUNTER_ACCESS = auto()
    DICT_COMPREHENSION = auto()
    ENUMERATE_ITER = auto()
    ZIP_ITER = auto()
    DICT_ITEMS_ITER = auto()
    DICT_KEYS_ITER = auto()
    DICT_VALUES_ITER = auto()
    RANGE_ITER = auto()
    ISINSTANCE_CHECK = auto()
    ISSUBCLASS_CHECK = auto()
    TYPE_CHECK = auto()
    NONE_CHECK = auto()
    CALLABLE_CHECK = auto()
    HASATTR_CHECK = auto()
    GETATTR_DEFAULT = auto()
    HASATTR_GETATTR = auto()
    LIST_APPEND = auto()
    LIST_EXTEND = auto()
    SET_ADD = auto()
    SET_DISCARD = auto()
    STRING_FORMAT = auto()
    STRING_JOIN = auto()
    STRING_SPLIT = auto()
    STRING_MULTIPLY = auto()
    TRY_EXCEPT_PATTERN = auto()
    CONTEXT_MANAGER = auto()
    TRUTHY_CHECK = auto()
    FALSY_CHECK = auto()
    OPTIONAL_CHAIN = auto()
    NULL_COALESCE = auto()
    TERNARY_NONE = auto()
    KEY_CHECK = auto()
    DICT_INT_KEY = auto()


@dataclass
class PatternMatch:
    """Result of matching a pattern."""

    kind: PatternKind
    confidence: float
    start_pc: int
    end_pc: int
    line: int | None = None
    variables: dict[str, object] = field(default_factory=dict[str, object])
    type_refinements: dict[str, PyType] = field(default_factory=dict[str, PyType])
    preconditions: list[str] = field(default_factory=list[str])
    guarantees: list[str] = field(default_factory=list[str])


__all__ = ["PatternKind", "PatternMatch"]
