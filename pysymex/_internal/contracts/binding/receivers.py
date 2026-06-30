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

"""Read-only receiver proxies for callable contract predicate tracing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    import z3


@dataclass(frozen=True, slots=True)
class ContractReceiverProxy:
    """Read-only view of modeled shallow scalar receiver attributes."""

    receiver_name: str
    attributes: Mapping[str, z3.ExprRef]

    def __getattr__(self, name: str) -> z3.ExprRef:
        """Return a modeled shallow scalar attribute or fail as unsupported."""
        try:
            return self.attributes[name]
        except KeyError as exc:
            msg = f"Unsupported receiver attribute reference: {self.receiver_name}.{name}"
            raise AttributeError(
                msg,
            ) from exc


def receiver_proxy_for_symbols(
    symbols: Mapping[str, z3.ExprRef],
    receiver_name: str,
) -> ContractReceiverProxy | None:
    """Build a read-only proxy from ``<receiver>.<attr>`` contract symbols."""
    prefix = f"{receiver_name}."
    attributes = {
        name.removeprefix(prefix): value
        for name, value in symbols.items()
        if name.startswith(prefix)
    }
    if not attributes:
        return None
    return ContractReceiverProxy(receiver_name=receiver_name, attributes=attributes)
