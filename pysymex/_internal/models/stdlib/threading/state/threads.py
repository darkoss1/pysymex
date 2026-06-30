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

"""Thread lifecycle model."""

from __future__ import annotations

from pysymex._internal.models.stdlib.threading.state.counters import thread_id_counter


class ThreadModel:
    """Symbolic model of ``threading.Thread``.

    Tracks thread lifecycle (created -> started -> alive -> dead).
    """

    def __init__(
        self,
        target: object = None,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
        name: str | None = None,
        daemon: bool = False,
    ) -> None:
        """Initialize a new ThreadModel instance."""
        self._thread_id = f"thread_{next(thread_id_counter)}"
        self.started = False
        self._alive = False
        self.args: tuple[object, ...] = args
        self.kwargs = kwargs or {}
        self.name = name or self._thread_id
        self.daemon = daemon

    @property
    def thread_id(self) -> str:
        return self._thread_id

    def start(self) -> None:
        """Mark thread as started and alive."""
        if self.started:
            msg = "threads can only be started once"
            raise RuntimeError(msg)
        self.started = True
        self._alive = True

    def join(self, timeout: float | None = None) -> None:
        """Mark thread as joined (no longer alive)."""
        self._alive = False

    def is_alive(self) -> bool:
        """Check if thread is currently running."""
        return self._alive

    def __repr__(self) -> str:
        status = "started" if self.started else "not started"
        alive = "alive" if self._alive else "dead"
        return f"ThreadModel({self.name}, {status}, {alive})"
