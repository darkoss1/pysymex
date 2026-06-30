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

"""Terminal-oriented builtin call models."""

from __future__ import annotations

from pysymex._internal.models.contracts.system_exit import SystemExitCallModel


class ExitModel(SystemExitCallModel):
    """Model for interactive builtin exit()."""

    name = "exit"
    qualname = "builtins.exit"
    source = "exit"


class QuitModel(SystemExitCallModel):
    """Model for interactive builtin quit()."""

    name = "quit"
    qualname = "builtins.quit"
    source = "quit"
