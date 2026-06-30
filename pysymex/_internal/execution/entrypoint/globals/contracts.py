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

"""PySyMex contract decorator global selection for function entrypoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.entrypoint.globals.inspection import (
    GlobalsInspection,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import CodeType


class ContractGlobals:
    """Domain owner for PySyMex contract decorator global selection."""

    @staticmethod
    def select(
        func: Callable[..., object],
        code: CodeType,
    ) -> dict[str, object]:
        """Return referenced PySyMex contract decorators safe to expose as globals."""
        globals_map = GlobalsInspection.globals_for(func)
        expected = ContractGlobals._decorators_by_name()
        selected: dict[str, object] = {}
        for name in GlobalsInspection.referenced_names(code):
            expected_decorator = expected.get(name)
            if expected_decorator is not None and globals_map.get(name) is expected_decorator:
                selected[name] = expected_decorator
        return selected

    @staticmethod
    def _decorators_by_name() -> dict[str, object]:
        """Return contract decorator functions by source-visible name."""
        from pysymex._internal.contracts.decorators import assigns, assumes, ensures, pure, requires

        return {
            "assigns": assigns,
            "assumes": assumes,
            "ensures": ensures,
            "pure": pure,
            "requires": requires,
        }
