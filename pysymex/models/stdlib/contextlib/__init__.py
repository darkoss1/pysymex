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

"""Models for the contextlib module."""

from __future__ import annotations

from pysymex.models.stdlib.contextlib.managers import (
    AsyncContextManagerModel,
    ContextDecoratorModel,
    ContextManagerFactory,
    ContextManagerModel,
    AsyncContextManager,
    ContextManager,
)
from pysymex.models.stdlib.contextlib.protocols import (
    AsyncContextManagerProtocol,
    ContextManagerProtocol,
    ExitCallback,
)
from pysymex.models.stdlib.contextlib.stacks import (
    AsyncExitStackModel,
    ExitStackConstructorModel,
    ExitStackModel,
    logger,
)
from pysymex.models.stdlib.contextlib.stubs import (
    RedirectStderr,
    RedirectStdout,
    Suppress,
    stub_aclosing,
    stub_closing,
    stub_redirect_stderr,
    stub_redirect_stdout,
)


CONTEXTLIB_MODELS: dict[str, object] = {
    "contextmanager": ContextManagerModel(),
    "asynccontextmanager": AsyncContextManagerModel(),
    "ContextDecorator": ContextDecoratorModel,
    "ExitStack": ExitStackModel,
    "AsyncExitStack": AsyncExitStackModel,
    "closing": stub_closing,
    "aclosing": stub_aclosing,
    "suppress": Suppress,
    "redirect_stdout": stub_redirect_stdout,
    "redirect_stderr": stub_redirect_stderr,
}


def get_contextlib_model(name: str) -> object | None:
    """Get a contextlib model by name."""
    return CONTEXTLIB_MODELS.get(name)


__all__ = [
    "AsyncContextManagerModel",
    "AsyncContextManagerProtocol",
    "AsyncExitStackModel",
    "CONTEXTLIB_MODELS",
    "ContextDecoratorModel",
    "ContextManagerFactory",
    "ContextManagerModel",
    "ContextManagerProtocol",
    "ExitCallback",
    "ExitStackConstructorModel",
    "ExitStackModel",
    "AsyncContextManager",
    "ContextManager",
    "RedirectStderr",
    "RedirectStdout",
    "Suppress",
    "stub_aclosing",
    "stub_closing",
    "stub_redirect_stderr",
    "stub_redirect_stdout",
    "get_contextlib_model",
    "logger",
]
