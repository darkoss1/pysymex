"""Tests for live pysymex._internal.config dataclass models."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.config.execution.verification import ExecutionVerificationConfig
from pysymex._internal.config.logging.settings import LoggerConfig
from pysymex._internal.config.sandbox.types import (
    SandboxBackend,
    SandboxConfig,
    SandboxResourceLimits,
    SecurityCapabilities,
)
from pysymex._internal.config.solver.floats import FloatConfig
from pysymex._internal.config.tracing.settings import TracerConfig


def test_config_implementations_live_under_internal_config_package() -> None:
    """Configuration implementation stays internal; there is no public config facade."""
    package_root = Path("pysymex")
    config_root = package_root / "_internal" / "config"
    public_facade = package_root / "config.py"
    offenders = [
        str(path)
        for path in package_root.rglob("config.py")
        if not path.is_relative_to(config_root)
    ]
    assert not public_facade.exists()
    assert config_root.is_dir()
    assert offenders == []


def test_domain_config_has_no_flat_legacy_modules() -> None:
    """Domain config implementations live under subpackages, not root-level buckets."""
    config_root = Path("pysymex") / "_internal" / "config"
    legacy_files = (
        "analysis.py",
        "concurrency.py",
        "detectors.py",
        "execution.py",
        "floats.py",
        "limits.py",
        "logging.py",
        "output.py",
        "sandbox_bridge.py",
        "sections.py",
        "solver.py",
        "tracing.py",
        "verification.py",
    )
    present_legacy_files = [
        str(config_root / file_name)
        for file_name in legacy_files
        if (config_root / file_name).exists()
    ]
    assert present_legacy_files == []


def test_ghost_profile_config_modules_stay_removed() -> None:
    """The old TOML/profile config graph must not return as a parallel runtime API."""
    config_root = Path("pysymex") / "_internal" / "config"
    removed_modules = (
        config_root / "root.py",
        config_root / "io.py",
        config_root / "analysis" / "detectors.py",
        config_root / "analysis" / "limits.py",
        config_root / "analysis" / "profile.py",
        config_root / "output" / "reporting.py",
        config_root / "solver" / "settings.py",
    )
    present = [str(path) for path in removed_modules if path.exists()]
    assert present == []


def test_runtime_config_classes_have_config_package_owners() -> None:
    """Runtime config dataclasses resolve from the config package."""
    assert ExecutionConfig.__module__ == "pysymex._internal.config.execution.settings"
    assert (
        ExecutionVerificationConfig.__module__ == "pysymex._internal.config.execution.verification"
    )
    assert ExecutionConfig is ExecutionConfig
    assert ExecutionVerificationConfig is ExecutionVerificationConfig


def test_config_sections_have_runtime_domain_package_owners() -> None:
    """Live config sections belong to the domains that consume them."""
    assert FloatConfig.__module__ == "pysymex._internal.config.solver.floats"
    assert LoggerConfig.__module__ == "pysymex._internal.config.logging.settings"
    assert SandboxBackend.__module__ == "pysymex._internal.config.sandbox.types"
    assert SandboxConfig.__module__ == "pysymex._internal.config.sandbox.types"
    assert SandboxResourceLimits.__module__ == "pysymex._internal.config.sandbox.types"
    assert SecurityCapabilities.__module__ == "pysymex._internal.config.sandbox.types"
    assert TracerConfig.__module__ == "pysymex._internal.config.tracing.settings"
