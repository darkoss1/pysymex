# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Entrypoint for the dedicated ``pysymex-verify`` console script."""

from __future__ import annotations

import sys

from pysymex.cli import main as _cli_main


def main(argv: list[str] | None = None) -> int:
    """Run the main CLI with the ``verify`` subcommand preselected."""
    args = list(argv) if argv is not None else sys.argv[1:]
    return _cli_main(["verify", *args])


if __name__ == "__main__":
    sys.exit(main())
