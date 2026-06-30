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

"""Base reporting formatter protocol."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.execution.results.result import ExecutionResult

logger = get_logger(__name__)


class Formatter(ABC):
    """Base class for output formatters."""

    name: str = "base"
    extension: str = ".txt"

    @abstractmethod
    def format(self, result: ExecutionResult) -> str:
        """Format the execution result."""

    def save(self, result: ExecutionResult, filepath: str) -> None:
        """Save formatted result to file."""
        content = self.format(result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("Saved %s report: %s", self.name, filepath)
