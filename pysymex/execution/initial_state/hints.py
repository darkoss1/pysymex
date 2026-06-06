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

"""Hint parsing for initial symbolic input construction."""

from __future__ import annotations

from pathlib import PurePath
import types
from typing import Union, get_args, get_origin

__all__ = ["hint_to_type_str", "parse_instance_type_hint"]


def hint_to_type_str(hint: object) -> str:
    """Convert a type hint to the symbolic input type string used by execution."""
    origin = get_origin(hint)
    if origin is not None:
        if origin is list:
            return "list"
        if origin is dict:
            return "dict"
        if origin is tuple:
            return "list"
        if origin in (types.UnionType, Union):
            args = get_args(hint)
            non_none_args = [arg for arg in args if arg is not type(None)]
            if len(non_none_args) != len(args):
                if len(non_none_args) == 1:
                    inner_type = hint_to_type_str(non_none_args[0])
                    if inner_type in {"any", "nullable", "optional"}:
                        return "nullable"
                    return f"optional:{inner_type}"
                return "nullable"
            for arg in non_none_args:
                return hint_to_type_str(arg)
            return "any"

    direct_hint = origin or hint
    if direct_hint is int:
        return "int"
    if direct_hint is float:
        return "float"
    if direct_hint is str:
        return "str"
    if direct_hint is bool:
        return "bool"
    if direct_hint is list:
        return "list"
    if direct_hint is dict:
        return "dict"
    if isinstance(direct_hint, type) and issubclass(direct_hint, PurePath):
        return "path"
    return "int"


def parse_instance_type_hint(type_hint: str) -> tuple[str, dict[str, str]]:
    """Parse ``instance:ClassName|param=hint,...`` scanner instance hints."""
    class_part, _, hint_part = type_hint.partition("|")
    class_name = class_part.split(":", 1)[1]
    init_type_hints: dict[str, str] = {}
    for item in hint_part.split(","):
        param_name, separator, hint = item.partition("=")
        if separator and param_name.isidentifier() and hint:
            init_type_hints[param_name] = hint.lower()
    return class_name, init_type_hints
