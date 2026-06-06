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

"""Shared structural base class for range-analysis mixin methods."""

from __future__ import annotations

from typing import Self


class RangeBaseMixin:
    low: int | None
    high: int | None
    is_empty: bool
    is_numeric: bool

    def __init__(
        self,
        low: int | None = None,
        high: int | None = None,
        is_empty: bool = False,
        is_numeric: bool = False,
    ) -> None:
        raise NotImplementedError

    @classmethod
    def empty(cls: type[Self]) -> Self:
        raise NotImplementedError

    @classmethod
    def full(cls: type[Self]) -> Self:
        raise NotImplementedError

    @classmethod
    def exact(cls: type[Self], value: int) -> Self:
        raise NotImplementedError

    @property
    def is_exact(self) -> bool:
        raise NotImplementedError

    def is_full(self) -> bool:
        raise NotImplementedError

    def contains(self, value: int) -> bool:
        raise NotImplementedError


__all__ = ["RangeBaseMixin"]
