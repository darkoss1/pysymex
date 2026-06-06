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

"""Source-line extraction for traced bytecode steps."""

from __future__ import annotations

import dis

from pysymex.logger import get_logger

logger = get_logger(__name__)


def instruction_source_line(instr: dis.Instruction) -> int | None:
    """Return the best source line attached to an instruction."""
    try:
        pos = getattr(instr, "positions", None)
        if pos is not None:
            lineno_raw = getattr(pos, "lineno", None)
            if isinstance(lineno_raw, int):
                return lineno_raw
        starts_line_raw = getattr(instr, "starts_line", None)
        if isinstance(starts_line_raw, int):
            return starts_line_raw
    except Exception:
        logger.debug("Failed to resolve instruction source line", exc_info=True)
        return None
    return None
