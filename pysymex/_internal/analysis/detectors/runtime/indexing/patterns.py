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

"""Index-error type-subscription and dict-access suppression heuristics."""

from __future__ import annotations

TYPE_SUBSCRIPTION_CONTAINERS = frozenset(
    (
        "list",
        "dict",
        "tuple",
        "set",
        "frozenset",
        "type",
        "sequence",
        "mapping",
        "iterable",
        "typing",
    ),
)
TYPE_SUBSCRIPTION_INDEXES = frozenset(
    (
        "int",
        "float",
        "str",
        "bool",
        "bytes",
        "object",
        "none",
        "nonetype",
        "list",
        "dict",
        "tuple",
        "set",
        "frozenset",
    ),
)
DICT_KEY_SUFFIXES = {
    "_id",
    "id",
    "key",
    "name",
    "feature",
    "tier",
    "type",
    "kind",
    "code",
    "mode",
    "command",
}
DICT_CONTAINER_PATTERNS = {
    "dict",
    "map",
    "cache",
    "tracker",
    "store",
    "registry",
    "config",
    "settings",
    "_recent",
    "_usage",
    "_count",
    "_limits",
    "_LIMITS",
    "_SIZE",
    "_join",
    "_command",
    "_confusion",
    "_requests",
}
SKIP_INDEX_PATTERNS = (
    "depth",
    "level",
    "count",
    "i",
    "j",
    "k",
    "n",
    "idx",
    "pos",
    "offset",
    "size",
    "length",
    "width",
    "height",
    "x",
    "y",
    "z",
)
INSTANCE_CONTAINER_PATTERNS = (
    "self.",
    "cls.",
    ".stack",
    ".elements",
    ".items",
    ".values",
    ".keys",
    ".methods",
    ".fields",
    ".attributes",
    ".properties",
    ".hooks",
    "._pending",
    "._alias",
    "._references",
    ".locals",
    ".globals",
    ".block_stack",
    "frame_copy",
    "closure_parent",
    "states",
)


class IndexErrorPatternMixin:
    """Shared symbolic-index false-positive suppression heuristics."""

    @staticmethod
    def _normalize_symbolic_name(raw_name: str) -> str:
        """Normalize container/index names for type-subscription matching."""
        normalized = raw_name.strip()
        normalized = normalized.removeprefix("global_")
        normalized = normalized.removeprefix("import_")
        normalized = normalized.removeprefix("builtins.")
        if normalized.startswith("<class '") and normalized.endswith("'>"):
            normalized = normalized[8:-2]
        return normalized.lower()

    def _is_type_subscription_pattern(self, container: object, index: object) -> bool:
        """Return True when BINARY_SUBSCR matches `list[int]`-style type usage."""
        container_name = getattr(container, "name", "") or ""
        index_name = getattr(index, "name", "") or ""
        normalized_container = self._normalize_symbolic_name(container_name)
        normalized_index = self._normalize_symbolic_name(index_name)

        if normalized_container.startswith("typing."):
            return True
        if normalized_container.startswith("collections.abc."):
            return True
        return (
            normalized_container in TYPE_SUBSCRIPTION_CONTAINERS
            and normalized_index in TYPE_SUBSCRIPTION_INDEXES
        )

    def _is_likely_dict_access(self, container: object, index: object) -> bool:
        """Check if this subscript is likely dict[key] rather than list[index]."""
        container_name = getattr(container, "name", "") or ""
        index_name = getattr(index, "name", "") or ""
        container_looks_like_dict = any(
            pattern in container_name.lower() for pattern in DICT_CONTAINER_PATTERNS
        )
        index_looks_like_key = any(
            index_name.lower().endswith(suffix) or suffix in index_name.lower()
            for suffix in DICT_KEY_SUFFIXES
        )
        container_is_instance_attr = any(
            pattern in container_name for pattern in INSTANCE_CONTAINER_PATTERNS
        )
        index_is_common_var = any(
            index_name == pattern or index_name.endswith(f"_{pattern}")
            for pattern in SKIP_INDEX_PATTERNS
        )
        return (
            container_looks_like_dict
            or index_looks_like_key
            or container_is_instance_attr
            or index_is_common_var
        )
