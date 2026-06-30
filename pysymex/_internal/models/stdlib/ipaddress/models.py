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

"""Models for the ipaddress standard-library module."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_int, const_string, symbolic_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class IpAddressModel(FunctionModel):
    """Model for ipaddress constructors."""

    aliases = ("ipaddress.ip_network", "ipaddress.ip_interface")
    name = "ip_address"
    qualname = "ipaddress.ip_address"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if args:
            text_or_int = const_string(args[0])
            if text_or_int is None:
                text_or_int = const_int(args[0])
            if text_or_int is not None:
                try:
                    return ModelResult(
                        value=SymbolicValue.from_const(ipaddress.ip_address(text_or_int)),
                    )
                except ValueError:
                    pass
        value, constraint = symbolic_object(f"ip_address_{state.pc}", "ipaddress.IPvXAddress")
        return ModelResult(value=value, constraints=[constraint])


ipaddress_models: list[FunctionModel] = [IpAddressModel()]
