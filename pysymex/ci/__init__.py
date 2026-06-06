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

"""CI/CD integration for pysymex — re-export hub.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides integrations for:
- GitHub Actions
- GitLab CI
- Pre-commit hooks
- Exit codes for CI pipelines
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.ci.github import GitHubActionsReporter as GitHubActionsReporter
    from pysymex.ci.gitlab import GitLabReporter as GitLabReporter
    from pysymex.ci.precommit import (
        generate_precommit_config as generate_precommit_config,
        generate_precommit_hook_script as generate_precommit_hook_script,
    )
    from pysymex.ci.runner import (
        CIRunner as CIRunner,
        run_ci_check as run_ci_check,
    )
    from pysymex.ci.types import (
        CIResult as CIResult,
        ExitCode as ExitCode,
        FailureThreshold as FailureThreshold,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "CIRunner": ("pysymex.ci.runner", "CIRunner"),
    "GitHubActionsReporter": ("pysymex.ci.github", "GitHubActionsReporter"),
    "GitLabReporter": ("pysymex.ci.gitlab", "GitLabReporter"),
    "generate_precommit_config": ("pysymex.ci.precommit", "generate_precommit_config"),
    "generate_precommit_hook_script": (
        "pysymex.ci.precommit",
        "generate_precommit_hook_script",
    ),
    "run_ci_check": ("pysymex.ci.runner", "run_ci_check"),
    "CIResult": ("pysymex.ci.types", "CIResult"),
    "ExitCode": ("pysymex.ci.types", "ExitCode"),
    "FailureThreshold": ("pysymex.ci.types", "FailureThreshold"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Dir."""
    return lazy_dir(_EXPORTS, globals(), include_namespace=False)


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
