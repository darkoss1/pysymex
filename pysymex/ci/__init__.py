"""CI/CD integration for PySyMex — re-export hub.

Provides integrations for:
- GitHub Actions
- GitLab CI
- Pre-commit hooks
- Exit codes for CI pipelines
"""

from pysymex.ci.core import CIRunner as CIRunner

from pysymex.ci.core import GitHubActionsReporter as GitHubActionsReporter

from pysymex.ci.core import GitLabReporter as GitLabReporter

from pysymex.ci.core import generate_precommit_config as generate_precommit_config

from pysymex.ci.core import generate_precommit_hook_script as generate_precommit_hook_script

from pysymex.ci.core import run_ci_check as run_ci_check

from pysymex.ci.types import CIResult as CIResult

from pysymex.ci.types import ExitCode as ExitCode

from pysymex.ci.types import FailureThreshold as FailureThreshold

__all__ = [
    "ExitCode",
    "CIResult",
    "FailureThreshold",
    "GitHubActionsReporter",
    "GitLabReporter",
    "CIRunner",
    "run_ci_check",
    "generate_precommit_config",
    "generate_precommit_hook_script",
]
