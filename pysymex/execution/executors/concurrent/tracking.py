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

"""Shared-variable access tracking for concurrent symbolic execution.

Records which thread identifiers touch each variable name so the concurrent
executor can flag data races when combined with
:class:`~pysymex.analysis.domains.concurrency.ConcurrencyAnalyzer`.
"""

from __future__ import annotations


class SharedVariableTracker:
    """Tracks variables accessed from multiple threads.

    A variable is considered "shared" once it has been accessed by
    two or more distinct thread IDs.
    """

    def __init__(self) -> None:
        """Create empty per-variable thread access maps."""
        self._accesses: dict[str, set[str]] = {}
        self._writes: dict[str, set[str]] = {}

    def record_access(
        self,
        thread_id: str,
        variable_name: str,
        is_write: bool = False,
    ) -> None:
        """Record a variable access by a thread.

        Args:
            thread_id: The identifier of the thread making the access.
            variable_name: The name of the variable being accessed.
            is_write: True if the access is a write operation, False if a read operation.
        """
        self._accesses.setdefault(variable_name, set()).add(thread_id)
        if is_write:
            self._writes.setdefault(variable_name, set()).add(thread_id)

    def is_shared(self, variable_name: str) -> bool:
        """Check if a variable has been accessed by multiple threads.

        Args:
            variable_name: The name of the variable to check.

        Returns:
            True if the variable is shared across multiple threads, False otherwise.
        """
        return len(self._accesses.get(variable_name, ())) >= 2


# Opcode names treated as memory stores when intercepting concurrent execution.
STORE_OPCODES = frozenset(
    {
        "STORE_FAST",
        "STORE_NAME",
        "STORE_GLOBAL",
        "STORE_DEREF",
        "STORE_ATTR",
    }
)

# Opcode names treated as memory loads when intercepting concurrent execution.
LOAD_OPCODES = frozenset(
    {
        "LOAD_FAST",
        "LOAD_NAME",
        "LOAD_GLOBAL",
        "LOAD_DEREF",
        "LOAD_ATTR",
    }
)

# Opcode names treated as thread/async API calls during concurrent interception.
CALL_OPCODES = frozenset(
    {
        "CALL",
        "CALL_FUNCTION",
        "CALL_METHOD",
        "CALL_FUNCTION_KW",
        "CALL_FUNCTION_EX",
    }
)
