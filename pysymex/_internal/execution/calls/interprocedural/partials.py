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

"""``functools.partial`` expansion for interprocedural call entry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class ExpandedPartialCall:
    """Underlying callable and merged arguments for a partial call."""

    func_obj: object
    args: list[StackValue]
    kwargs: dict[str, StackValue]


def expand_partial_call(
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> ExpandedPartialCall | None:
    """Return merged call arguments for a modeled ``functools.partial`` target."""
    from pysymex._internal.models.stdlib.functools.core import PartialModel

    if not isinstance(func_obj, PartialModel):
        return None

    bound_args = [cast("StackValue", value) for value in func_obj.args]
    bound_kwargs = {name: cast("StackValue", value) for name, value in func_obj.kwargs.items()}
    bound_kwargs.update(kwargs)
    return ExpandedPartialCall(
        func_obj=func_obj.func,
        args=[*bound_args, *args],
        kwargs=bound_kwargs,
    )
