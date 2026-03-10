"""CI/CD integration for PySyMex — re-export hub.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Provides integrations for:
- GitHub Actions
- GitLab CI
- Pre-commit hooks
- Exit codes for CI pipelines
"""

from __future__ import annotations

from importlib import import_module

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
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.ci' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
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
