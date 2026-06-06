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

"""Compiled pattern tables for suppressing known false-positive detections."""

from __future__ import annotations

import re

TYPING_FP_PATTERNS = [
    "Attempting to subscript import_Callable",
    "Attempting to subscript Callable",
    "Attempting to subscript ParamSpec",
    "Attempting to subscript TypeVar",
    "Attempting to subscript Protocol",
    "Attempting to subscript Generic",
    "Attempting to subscript Optional",
    "Attempting to subscript Union",
    "Attempting to subscript Literal",
    "Attempting to subscript Annotated",
    "Attempting to subscript ClassVar",
    "Attempting to subscript Final",
    "Attempting to subscript Type",
    "import_TYPE_CHECKING",
    "TYPE_CHECKING",
    "typing.",
    "typing_extensions.",
    "Index global_list",
    "Index global_dict",
    "Index global_tuple",
    "Index global_set",
    "Index global_frozenset",
    "Index global_type",
    "Index global_bytes",
    "Index global_str",
    "Index global_int",
    "Index global_float",
    "Index global_bool",
    "Index import_",
]

INTENTIONAL_ASSERTION_PATTERNS = [
    re.compile(r"if.*PRODUCTION", re.IGNORECASE),
    re.compile(r"if.*DEBUG", re.IGNORECASE),
    re.compile(r"if.*config\.", re.IGNORECASE),
    re.compile(r"if.*settings\.", re.IGNORECASE),
    re.compile(r"if.*ENV", re.IGNORECASE),
    re.compile(r"def\s+(validate|sanitize|check|verify|ensure|assert_)", re.IGNORECASE),
    re.compile(r"raise\s+ValueError\("),
    re.compile(r"raise\s+TypeError\("),
    re.compile(r"raise\s+RuntimeError\("),
    re.compile(r"raise\s+AssertionError\("),
    re.compile(r"if\s+not\s+\w+:\s*raise"),
    re.compile(r"if\s+\w+\s+is\s+None:\s*raise"),
    re.compile(r"assert\s+\w+\s+is\s+not\s+None"),
]

DICT_CONTAINER_PATTERNS = frozenset(
    {
        "dict",
        "map",
        "cache",
        "tracker",
        "store",
        "registry",
        "config",
        "settings",
        "lookup",
        "index",
        "table",
        "_recent",
        "_usage",
        "_count",
        "_limits",
    }
)

__all__ = ["DICT_CONTAINER_PATTERNS", "INTENTIONAL_ASSERTION_PATTERNS", "TYPING_FP_PATTERNS"]
