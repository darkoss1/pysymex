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

"""Invocation-scoped capabilities supplied to symbolic models."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Generator

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.models.contracts.results import ModelResult
    from pysymex._internal.typing.protocols import StackValue


class ModelInvoker(Protocol):
    """Invoke another registered model through the runtime composition root."""

    def __call__(
        self,
        name: str,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult | None: ...


_model_invoker: ContextVar[ModelInvoker | None] = ContextVar(
    "model_invoker",
    default=None,
)


@contextmanager
def bind_model_invoker(invoker: ModelInvoker) -> Generator[None]:
    """Bind nested model dispatch for one top-level model invocation."""
    token = _model_invoker.set(invoker)
    try:
        yield
    finally:
        _model_invoker.reset(token)


def invoke_registered_model(
    name: str,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    state: VMState,
) -> ModelResult | None:
    """Invoke a canonical model when called inside execution dispatch."""
    invoker = _model_invoker.get()
    if invoker is None:
        return None
    return invoker(name, args, kwargs, state)
