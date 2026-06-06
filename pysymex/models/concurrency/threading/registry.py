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

from __future__ import annotations

from pysymex.models.concurrency.threading.locks import (
    BoundedSemaphoreModel,
    LockModel,
    RLockModel,
    SemaphoreModel,
)
from pysymex.models.concurrency.threading.sync import BarrierModel, ConditionModel, EventModel
from pysymex.models.concurrency.threading.threads import ThreadModel

THREADING_MODELS: dict[str, object] = {
    "Thread": ThreadModel,
    "Lock": LockModel,
    "RLock": RLockModel,
    "Semaphore": SemaphoreModel,
    "BoundedSemaphore": BoundedSemaphoreModel,
    "Event": EventModel,
    "Condition": ConditionModel,
    "Barrier": BarrierModel,
}


def get_threading_model(name: str) -> object | None:
    """Look up a threading model by name."""
    return THREADING_MODELS.get(name)
