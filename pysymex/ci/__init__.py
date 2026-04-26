# pysymex: Python Symbolic Execution & Formal Verification
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

"""CI/CD integration for pysymex — re-export hub.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides integrations for:
- GitHub Actions
- GitLab CI
- Pre-commit hooks
- Exit codes for CI pipelines
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.ci.core import (
        CIRunner as CIRunner,
        GitHubActionsReporter as GitHubActionsReporter,
        GitLabReporter as GitLabReporter,
        generate_precommit_config as generate_precommit_config,
        generate_precommit_hook_script as generate_precommit_hook_script,
        run_ci_check as run_ci_check,
    )
    from pysymex.ci.types import (
        CIResult as CIResult,
        ExitCode as ExitCode,
        FailureThreshold as FailureThreshold,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "CIRunner": ("pysymex.ci.core", "CIRunner"),
    "GitHubActionsReporter": ("pysymex.ci.core", "GitHubActionsReporter"),
    "GitLabReporter": ("pysymex.ci.core", "GitLabReporter"),
    "generate_precommit_config": ("pysymex.ci.core", "generate_precommit_config"),
    "generate_precommit_hook_script": ("pysymex.ci.core", "generate_precommit_hook_script"),
    "run_ci_check": ("pysymex.ci.core", "run_ci_check"),
    "CIResult": ("pysymex.ci.types", "CIResult"),
    "ExitCode": ("pysymex.ci.types", "ExitCode"),
    "FailureThreshold": ("pysymex.ci.types", "FailureThreshold"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.ci' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return list(_EXPORTS.keys())


__all__: list[str] = [
    "CIResult",
    "CIRunner",
    "ExitCode",
    "FailureThreshold",
    "GitHubActionsReporter",
    "GitLabReporter",
    "generate_precommit_config",
    "generate_precommit_hook_script",
    "run_ci_check",
]
