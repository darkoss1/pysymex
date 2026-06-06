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

"""Verify lock acquire/release pairing and ordering safety."""

from __future__ import annotations

from types import CodeType

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.domains.resources.usage import (
    ResourceKind,
    ResourceWarning,
    extract_call_argc,
    is_counted_resource_call,
)
from pysymex.core.cache import get_instructions as cached_get_instructions


class LockSafetyAnalyzer:
    """Analyzes lock acquisition and release patterns."""

    def analyze(
        self,
        code: CodeType,
        file_path: str = "<unknown>",
    ) -> list[ResourceWarning]:
        """Analyze lock usage for potential issues."""
        warnings: list[ResourceWarning] = []
        instructions = cached_get_instructions(code)
        current_line = code.co_firstlineno
        acquired_locks: dict[str, int] = {}
        loading_var: str | None = None
        loading_attr: str | None = None
        last_acquire_var: str | None = None
        for instr in instructions:
            line = get_starts_line(instr)
            if line is not None:
                current_line = line
            opname = instr.opname
            arg = instr.argval
            if opname in {"BEFORE_WITH", "BEFORE_ASYNC_WITH"}:
                loading_var, loading_attr, last_acquire_var = self._clear_context_lock(
                    acquired_locks, loading_var, last_acquire_var
                )
                continue
            if opname in {"WITH_EXCEPT_START", "WITH_CLEANUP_START", "WITH_CLEANUP_FINISH"}:
                continue
            if opname in {"GET_AWAITABLE", "SEND", "END_SEND", "YIELD_VALUE", "RESUME"}:
                continue
            if opname in {"LOAD_FAST", "LOAD_NAME"}:
                loading_var = str(arg)
                loading_attr = None
            elif opname in {"LOAD_ATTR", "LOAD_METHOD"}:
                loading_attr = self._lock_attr(str(arg), loading_var)
            elif is_counted_resource_call(instr):
                last_acquire_var = self._handle_call(
                    warnings,
                    acquired_locks,
                    loading_var,
                    loading_attr,
                    extract_call_argc(instr),
                    current_line,
                    file_path,
                )
                loading_var = None
                loading_attr = None
            elif opname in {"RETURN_VALUE", "RETURN_CONST"}:
                self._warn_unreleased(warnings, acquired_locks, file_path)
        return warnings

    @staticmethod
    def _clear_context_lock(
        acquired_locks: dict[str, int],
        loading_var: str | None,
        last_acquire_var: str | None,
    ) -> tuple[None, None, None]:
        if loading_var and loading_var in acquired_locks:
            del acquired_locks[loading_var]
        if last_acquire_var and last_acquire_var in acquired_locks:
            del acquired_locks[last_acquire_var]
        return None, None, None

    @staticmethod
    def _lock_attr(attr: str, loading_var: str | None) -> str | None:
        if loading_var and attr in {"acquire", "release", "__enter__", "__exit__"}:
            return attr
        return None

    def _handle_call(
        self,
        warnings: list[ResourceWarning],
        acquired_locks: dict[str, int],
        loading_var: str | None,
        loading_attr: str | None,
        argc: int,
        current_line: int,
        file_path: str,
    ) -> str | None:
        if not (loading_var and loading_attr):
            return None
        if loading_attr in {"acquire", "__enter__"}:
            acquired_locks[loading_var] = current_line
            return loading_var
        if loading_attr in {"release", "__exit__"}:
            if loading_attr == "release" and argc != 0:
                return None
            if loading_var in acquired_locks:
                del acquired_locks[loading_var]
            else:
                warnings.append(
                    ResourceWarning(
                        kind="LOCK_RELEASED_NOT_ACQUIRED",
                        file=file_path,
                        line=current_line,
                        resource_kind=ResourceKind.LOCK,
                        resource_name=loading_var,
                        message=f"Lock '{loading_var}' released without being acquired",
                    )
                )
        return None

    @staticmethod
    def _warn_unreleased(
        warnings: list[ResourceWarning],
        acquired_locks: dict[str, int],
        file_path: str,
    ) -> None:
        for lock_name, acquire_line in acquired_locks.items():
            warnings.append(
                ResourceWarning(
                    kind="LOCK_NOT_RELEASED",
                    file=file_path,
                    line=acquire_line,
                    resource_kind=ResourceKind.LOCK,
                    resource_name=lock_name,
                    message=(
                        f"Lock '{lock_name}' acquired on line {acquire_line} "
                        f"may not be released before return"
                    ),
                )
            )


__all__ = ["LockSafetyAnalyzer"]
