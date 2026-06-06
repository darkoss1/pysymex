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

"""Exception contract declarations and decorators."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.types.scalars.values import is_list_of_objects


@dataclass(frozen=True, slots=True)
class RaisesContract:
    """Declarative exception type and optional display metadata for ``@raises``.

    Notes:
        ``condition`` is stored but is not evaluated by :meth:`matches`.
        ``message`` constrains matching only when the modeled exception also
        carries a non-empty message.
    """

    exc_type: type[BaseException] | str
    condition: str | None = None
    message: str | None = None

    @property
    def type_name(self) -> str:
        """Return the concrete class name or symbolic exception type label."""
        if isinstance(self.exc_type, type):
            return self.exc_type.__name__
        return str(self.exc_type)

    def matches(self, exc: SymbolicException) -> bool:
        """Return whether ``exc`` satisfies the implemented type/message match."""
        if isinstance(self.exc_type, type):
            if isinstance(exc.exc_type, type):
                if not issubclass(exc.exc_type, self.exc_type):
                    return False
            else:
                if exc.type_name != self.type_name:
                    return False
        else:
            if exc.type_name != self.exc_type:
                return False
        if self.message and exc.message:
            if self.message not in exc.message:
                return False
        return True


class _RaisesAnnotated(Protocol):
    """Callable-like object that carries normalized ``@raises`` metadata."""

    __raises__: list[RaisesContract]


def raises(
    exc_type: type[BaseException] | str,
    when: str | None = None,
    message: str | None = None,
) -> Callable[[Callable[..., object]], Callable[..., object]]:
    """Attach a :class:`RaisesContract` to a callable's ``__raises__`` list.

    Notes:
        The decorator records metadata for later analysis; it does not enforce
        the declared exception behavior at runtime.
    """
    contract = RaisesContract(exc_type, when, message)

    def _ensure_raises_list(annotated: _RaisesAnnotated) -> list[RaisesContract]:
        """Return a normalized mutable contract list attached to ``annotated``."""
        existing_attr = getattr(annotated, "__raises__", None)
        if is_list_of_objects(existing_attr):
            normalized: list[RaisesContract] = []
            for item in existing_attr:
                if isinstance(item, RaisesContract):
                    normalized.append(item)
            annotated.__raises__ = normalized
            return normalized
        normalized = []
        annotated.__raises__ = normalized
        return normalized

    def decorator(func: Callable[..., object]) -> Callable[..., object]:
        """Append this contract to ``func`` and return the same callable."""
        annotated_func = cast("_RaisesAnnotated", func)
        raises_list = _ensure_raises_list(annotated_func)
        raises_list.append(contract)
        return func

    return decorator
