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

"""Non-scan CLI commands for pysymex (analyze, benchmark, verify, etc.)."""

from __future__ import annotations

from pysymex.cli.commands.analyze import cmd_analyze
from pysymex.cli.commands.benchmark import cmd_benchmark
from pysymex.cli.commands.check import cmd_check
from pysymex.cli.commands.completion import generate_completion
from pysymex.cli.commands.verify import cmd_verify

__all__ = [
    "cmd_analyze",
    "cmd_benchmark",
    "cmd_check",
    "cmd_verify",
    "generate_completion",
]
