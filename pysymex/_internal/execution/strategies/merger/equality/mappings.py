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

"""Mapping and retained caller-stack equality for state merging."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.strategies.merger.types import StateMergerMixinContract

if TYPE_CHECKING:
    from collections.abc import Mapping


class MappingEqualityMixin(StateMergerMixinContract):
    """Compare mapping-like state payloads through structural value equality."""

    def _frame_caller_stack_equal(
        self,
        left: tuple[object, ...] | None,
        right: tuple[object, ...] | None,
    ) -> bool:
        """Compare caller stack snapshots retained in suspended call frames."""
        if left is None or right is None:
            return left is right
        return len(left) == len(right) and all(
            self.values_structurally_equal(l_value, r_value)
            for l_value, r_value in zip(left, right, strict=False)
        )

    def mapping_hash_mismatch(
        self,
        left: Mapping[str, object],
        right: Mapping[str, object],
    ) -> bool:
        """Fast-fail if both mappings expose content hashes and they differ."""
        left_hash_getter = getattr(left, "hash_value", None)
        right_hash_getter = getattr(right, "hash_value", None)
        if callable(left_hash_getter) and callable(right_hash_getter):
            left_hash = left_hash_getter()
            right_hash = right_hash_getter()
            if isinstance(left_hash, int) and isinstance(right_hash, int):
                return left_hash != right_hash
        return False

    def mapping_equal(self, left: Mapping[str, object], right: Mapping[str, object]) -> bool:
        """Compare string-keyed mappings using structural value equality."""
        if left is right:
            return True
        if len(left) != len(right):
            return False
        if self.mapping_hash_mismatch(left, right):
            return False
        for key, value in left.items():
            if key not in right:
                return False
            if not self.values_structurally_equal(value, right[key]):
                return False
        return True
