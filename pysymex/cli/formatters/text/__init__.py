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

"""Human-readable text/Rich formatters for scan results."""

from __future__ import annotations

import importlib.util
from typing import Any, Sequence

from pysymex.cli.formatters.text.symbolic import SymbolicTextMixin
from pysymex.cli.formatters.text.verify import VerifyTextMixin

__all__ = ["TextFormatter"]


class TextFormatter(SymbolicTextMixin, VerifyTextMixin):
    """Outputs human-readable CLI reports, using Rich if available."""

    def __init__(self, use_rich: bool = True):
        """Initialize the text formatter.

        Args:
            use_rich (bool): Whether to attempt importing and using the 'rich' library for formatted output.
                Defaults to True.
        """
        self.use_rich = use_rich
        if self.use_rich:
            self.has_rich = importlib.util.find_spec("rich") is not None
        else:
            self.has_rich = False

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        """Format symbolic execution scan results as a human-readable text report."""
        if self.has_rich:
            return self._format_symbolic_rich(results, total, reproduce, duration)
        return self._format_symbolic_ascii(results, total, reproduce, duration)

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        """Format formal verification results as a human-readable text report."""
        if self.has_rich:
            return self._format_verify_rich(results, total, duration)
        return self._format_verify_ascii(results, total, duration)
