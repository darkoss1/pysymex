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

"""Models for interactive builtins that display host-provided text."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.models.builtins.base import FunctionModel, ModelResult, none_model_result

from ..core.helpers import type_error_side_effect

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue


class InteractiveOutputModel(FunctionModel):
    """Abstract environment-dependent display text while preserving call behavior."""

    max_positional_args = 0

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        _ = state
        if len(args) > self.max_positional_args or kwargs:
            return none_model_result(
                type_error_side_effect(
                    f"builtins.{self.name}", f"{self.name}() received invalid arguments"
                )
            )
        return none_model_result({"io": True})


class HelpModel(InteractiveOutputModel):
    """Model for interactive builtin help()."""

    name = "help"
    qualname = "builtins.help"
    max_positional_args = 1


class CopyrightModel(InteractiveOutputModel):
    """Model for interactive builtin copyright()."""

    name = "copyright"
    qualname = "builtins.copyright"


class CreditsModel(InteractiveOutputModel):
    """Model for interactive builtin credits()."""

    name = "credits"
    qualname = "builtins.credits"


class LicenseModel(InteractiveOutputModel):
    """Model for interactive builtin license()."""

    name = "license"
    qualname = "builtins.license"
