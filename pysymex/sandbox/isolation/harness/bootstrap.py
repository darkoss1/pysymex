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

"""Render jail setup for a generated sandbox harness.

The bootstrap validates the staged target filename and prepares the target
namespace builtins. OS-native isolation backends enforce the security boundary.
"""

from __future__ import annotations

import textwrap


def render_bootstrap() -> str:
    """Render filename validation and target builtins for the harness."""
    return textwrap.dedent("""\
        # ===================================================================
        # PySymEx sandbox harness — auto-generated, do not edit
        # ===================================================================
        \"\"\"Sandbox execution wrapper.

        Invocation: python _sandbox_harness.py <target_filename>
        \"\"\"
        import os as _os
        import sys as _sys
        import builtins as _builtins_mod

        if len(_sys.argv) < 2:
            _sys.exit("sandbox-harness: no target filename provided")
        _target_name: str = _sys.argv[1]

        if ("/" in _target_name or "\\\\" in _target_name or ".." in _target_name
                or _target_name.startswith(".") or _target_name.startswith("-")):
            _sys.exit("sandbox-harness: invalid target filename")

        _safe_chars = frozenset(
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789_-."
        )
        if not all(ch in _safe_chars for ch in _target_name):
            _sys.exit("sandbox-harness: illegal characters in filename")

        _jail_root: str = _os.path.abspath(
            _os.environ.get("PYSYMEX_SANDBOX_JAIL", _os.getcwd())
        )
        _target: str = _os.path.join(_jail_root, _target_name)
        _target_builtins: dict[str, object] = dict(_builtins_mod.__dict__)

        """)
