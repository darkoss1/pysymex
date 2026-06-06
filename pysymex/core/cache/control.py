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

"""Process-local cache control for fresh analysis runs."""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar, Token

_PROCESS_CACHES_DISABLED: ContextVar[bool] = ContextVar(
    "_PROCESS_CACHES_DISABLED",
    default=False,
)
ProcessCacheClearer = Callable[[], None]
_PROCESS_CACHE_CLEARERS: dict[str, ProcessCacheClearer] = {}


def is_process_cache_disabled() -> bool:
    """Return whether the current run must bypass process-local caches."""
    return _PROCESS_CACHES_DISABLED.get()


def register_process_cache_clearer(name: str, clearer: ProcessCacheClearer) -> None:
    """Register a process-local cache clearer with the cache-control owner.

    Cache-owning modules register themselves instead of being imported by this
    lower-level module. Re-registering the same ``name`` replaces the previous
    callback so module reloads keep deterministic ownership.
    """
    if not name:
        raise ValueError("cache clearer name must be non-empty")
    _PROCESS_CACHE_CLEARERS[name] = clearer


@contextmanager
def process_caches_disabled(enabled: bool = True) -> Generator[None]:
    """Temporarily bypass and clear process-local caches for a fresh run.

    Persistent on-disk caches are not deleted here. This helper owns the
    process-local freshness contract used by scan ``no_cache`` mode.
    """
    if not enabled:
        yield
        return

    clear_process_caches()
    token: Token[bool] = _PROCESS_CACHES_DISABLED.set(True)
    try:
        yield
    finally:
        _PROCESS_CACHES_DISABLED.reset(token)
        clear_process_caches()


def clear_process_caches() -> None:
    """Clear cache surfaces that can affect same-process scan freshness."""
    for _name, clear_cache in tuple(sorted(_PROCESS_CACHE_CLEARERS.items())):
        clear_cache()


__all__ = [
    "clear_process_caches",
    "is_process_cache_disabled",
    "process_caches_disabled",
    "register_process_cache_clearer",
]
