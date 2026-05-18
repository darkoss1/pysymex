# pysymex: Python Symbolic Execution & Formal Verification
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

"""Shared lazy re-export helpers for package ``__init__`` modules."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from importlib import import_module

LazyExports = Mapping[str, tuple[str, str]]


def lazy_getattr(
    name: str,
    package_name: str,
    exports: LazyExports,
    namespace: dict[str, object],
) -> object:
    """Resolve and cache a lazily exported symbol."""
    target = exports.get(name)
    if target is None:
        raise AttributeError(f"module {package_name!r} has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    namespace[name] = value
    return value


def lazy_dir(
    exports: LazyExports,
    namespace: Mapping[str, object],
    extra: Iterable[str] = (),
    include_namespace: bool = True,
) -> list[str]:
    """Return the exported names for a lazy package module."""
    names = set(exports.keys())
    names.update(extra)
    if include_namespace:
        names.update(namespace.keys())
    return sorted(names)
