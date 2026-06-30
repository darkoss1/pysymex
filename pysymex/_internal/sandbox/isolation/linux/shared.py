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

"""Define Linux launcher names, lookup paths, and the x86_64 syscall list.

The Linux launcher generator consumes these constants when it emits an
in-namespace seccomp filter. This module contains policy data only and does
not install namespaces or filters.
"""

from __future__ import annotations

from typing import Final

SYSCALL_ALLOWLIST_X86_64: Final[frozenset[int]] = frozenset(
    (
        0,
        1,
        2,
        3,
        5,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        16,
        17,
        21,
        28,
        35,
        60,
        72,
        79,
        89,
        97,
        102,
        104,
        107,
        108,
        110,
        158,
        202,
        204,
        217,
        218,
        228,
        231,
        257,
        262,
        273,
        302,
        318,
        332,
        334,
        439,
    ),
)
LINUX_LAUNCHER_FILENAME: Final[str] = "_linux_sandbox_launcher.py"
UNSHARE_SEARCH_PATH: Final[str] = "/usr/sbin:/usr/bin:/sbin:/bin"
