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

"""Pre-commit configuration templates."""

from __future__ import annotations


def generate_precommit_config() -> str:
    """Generate .pre-commit-config.yaml content."""
    return """# pysymex pre-commit hook
repos:
  - repo: local
    hooks:
      - id: pysymex
        name: pysymex Security Check
        entry: pysymex check
        language: system
        types: [python]
        pass_filenames: true
        # Fail on high severity issues
        args: ["--fail-on", "high"]
"""


def generate_precommit_hook_script() -> str:
    """Generate a standalone pre-commit hook script."""
    return '''#!/usr/bin/env python3
"""pysymex pre-commit hook.
Install with: cp this_file .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
"""
import subprocess
import sys
def main():
    # Get staged Python files
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
    )
    files = [f for f in result.stdout.strip().split("\\n") if f.endswith(".py")]
    if not files:
        return 0
    # Run pysymex
    cmd = ["pysymex", "check", "--fail-on", "high"] + files
    result = subprocess.run(cmd)
    return result.returncode
if __name__ == "__main__":
    sys.exit(main())
'''


__all__ = ["generate_precommit_config", "generate_precommit_hook_script"]
