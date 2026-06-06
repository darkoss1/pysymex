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

"""Build unfiltered Python builtin mappings for symbolic execution setup."""

from __future__ import annotations

import builtins

from pysymex.core.exceptions.builtins import BUILTIN_EXCEPTIONS


def get_all_builtins() -> dict[str, object]:
    """Return an unfiltered mapping of public builtin names and special entries.

    Notes:
        The mapping includes import and class-construction functions and is
        not a sandbox policy.
    """
    builtin_dict: dict[str, object] = {}

    for name in dir(builtins):
        if name.startswith("_"):
            continue
        builtin_dict[name] = getattr(builtins, name)

    for exc_type in BUILTIN_EXCEPTIONS:
        builtin_dict[exc_type.__name__] = exc_type

    builtin_dict["__build_class__"] = __build_class__
    builtin_dict["__import__"] = __import__

    builtin_dict["True"] = True
    builtin_dict["False"] = False
    builtin_dict["None"] = None
    builtin_dict["Ellipsis"] = Ellipsis
    builtin_dict["__debug__"] = __debug__

    return builtin_dict
