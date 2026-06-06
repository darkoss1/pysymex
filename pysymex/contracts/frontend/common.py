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

"""Shared frontend adapter diagnostics."""

from __future__ import annotations


class UnsupportedFrontendSyntax(ValueError):
    """Raised when a frontend declaration cannot be normalized safely."""

    def __init__(
        self,
        frontend: str,
        message: str,
        *,
        line_number: int | None = None,
    ) -> None:
        """Create a frontend syntax error with stable user-facing context."""
        location = f" at line {line_number}" if line_number is not None else ""
        super().__init__(f"{frontend} frontend unsupported syntax{location}: {message}")
        self.frontend = frontend
        self.line_number = line_number


__all__ = ["UnsupportedFrontendSyntax"]
