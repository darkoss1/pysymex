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

"""Assemble Python harness source consumed by sandbox isolation backends.

The harness validates the staged filename, compiles the target source, and
executes it under normal Python builtins. Platform backends provide the
security boundary via process, filesystem, network, and syscall isolation.
"""

from __future__ import annotations

from pysymex.sandbox.isolation.constants import HARNESS_FILENAME

from .audit import render_compile
from .bootstrap import render_bootstrap
from .execution import render_execution
from .validation import render_load_source


def generate_harness_script() -> str:
    """Build the generated Python wrapper used to invoke a staged target."""
    return "".join(
        (
            render_bootstrap(),
            render_load_source(),
            render_compile(),
            render_execution(),
        )
    )


__all__ = ["HARNESS_FILENAME", "generate_harness_script"]
