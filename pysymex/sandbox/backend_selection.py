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

"""Report availability and advertised capabilities for sandbox backends.

This module supports backend selection and strength reporting. It probes
platform prerequisites and compares capability flags; it does not set up or
execute a sandbox.
"""

from __future__ import annotations

from importlib.util import find_spec
import sys

from .types import SandboxBackendStrength, SandboxConfig, SecurityCapabilities

_STRICT_DEFAULT_REQUIRED_CAPABILITIES: SecurityCapabilities = SecurityCapabilities(
    process_isolation=True,
    filesystem_jail=True,
    network_blocking=True,
    syscall_filtering=True,
    memory_limits=True,
    cpu_limits=True,
    process_limits=True,
)

_windows_appcontainer_auto_disabled_reason: str | None = None


def strict_default_required_capabilities() -> SecurityCapabilities:
    """Return capabilities required for automatic strict-backend selection.

    Returns:
        Required capability flags, omitting syscall filtering on Windows where
        the AppContainer backend reports no syscall-filtering capability.
    """
    if sys.platform == "win32":
        return SecurityCapabilities(
            process_isolation=True,
            filesystem_jail=True,
            network_blocking=True,
            syscall_filtering=False,
            memory_limits=True,
            cpu_limits=True,
            process_limits=True,
        )
    return _STRICT_DEFAULT_REQUIRED_CAPABILITIES


def missing_capabilities(
    required: SecurityCapabilities,
    actual: SecurityCapabilities,
) -> list[str]:
    """Return required capability names absent from an actual capability set.

    Args:
        required: Flags the caller requires from a sandbox backend.
        actual: Flags reported by the candidate or initialized backend.

    Returns:
        Dataclass field names enabled in `required` and disabled in `actual`.
    """
    missing: list[str] = []
    for name in SecurityCapabilities.__dataclass_fields__:
        if getattr(required, name) and not getattr(actual, name):
            missing.append(name)
    return missing


def strength_from_capabilities(capabilities: SecurityCapabilities) -> SandboxBackendStrength:
    """Classify a backend from the capability flags provided by its caller.

    Args:
        capabilities: Backend capability flags to classify.

    Returns:
        `STRONG` when all six required process, jail, network, and resource
        flags are true; `EXPERIMENTAL` when any capability is true; otherwise
        `UNAVAILABLE`.

    Notes:
        Syscall filtering is not included in the `STRONG` classification test.
        This helper trusts the supplied capability record and does not verify
        enforcement itself.
    """
    strong_fields = (
        "process_isolation",
        "filesystem_jail",
        "network_blocking",
        "memory_limits",
        "cpu_limits",
        "process_limits",
    )
    if all(bool(getattr(capabilities, name)) for name in strong_fields):
        return SandboxBackendStrength.STRONG
    if any(bool(getattr(capabilities, name)) for name in SecurityCapabilities.__dataclass_fields__):
        return SandboxBackendStrength.EXPERIMENTAL
    return SandboxBackendStrength.UNAVAILABLE


def check_linux_namespace_support() -> bool:
    """Check for the Linux command and kernel setting used by namespace setup.

    Returns:
        Whether `unshare` is available in the fixed system search path and
        unprivileged user namespaces are not disabled by the probed procfs
        setting. A missing procfs setting is treated as available.

    Limitations:
        The probe does not attempt sandbox setup or test all namespace,
        seccomp, or jail requirements.
    """
    import shutil

    if shutil.which("unshare", path="/usr/sbin:/usr/bin:/sbin:/bin") is None:
        return False
    try:
        with open("/proc/sys/kernel/unprivileged_userns_clone") as fh:
            return fh.read().strip() == "1"
    except FileNotFoundError:
        return True
    except Exception:
        return False


def check_windows_appcontainer_support() -> bool:
    """Check whether automatic AppContainer selection may be attempted.

    Returns:
        `True` only on Windows when automatic selection has not been disabled
        and the native backend support probe succeeds.

    Limitations:
        This is an availability probe; backend setup performs security-boundary
        verification separately.
    """
    if _windows_appcontainer_auto_disabled_reason is not None:
        return False
    if sys.platform != "win32":
        return False
    try:
        from .isolation.windows.appcontainer.backend import has_windows_appcontainer_support

        return has_windows_appcontainer_support()
    except Exception:
        return False


def disable_windows_appcontainer_auto(reason: str | None = None) -> None:
    """Disable later automatic AppContainer support checks in this process.

    Args:
        reason: Recorded disablement reason. When omitted, a setup self-check
            failure message is stored.

    Side Effects:
        Sets process-global state consumed by
        `check_windows_appcontainer_support`.
    """
    global _windows_appcontainer_auto_disabled_reason
    _windows_appcontainer_auto_disabled_reason = reason or "setup self-check failed"


def check_wasm_support(config: SandboxConfig | None = None) -> bool:
    """Check whether a WASI Python artifact is resolvable for execution.

    Args:
        config: Sandbox configuration used to resolve the WASI Python module.
            Defaults to a new `SandboxConfig` instance.

    Returns:
        Whether `wasmtime` is importable and a configured or discoverable
        WASI Python module resolves.

    Limitations:
        This probe does not instantiate or execute the WebAssembly backend.
    """
    if config is None:
        config = SandboxConfig()
    if find_spec("wasmtime") is None:
        return False
    from .isolation.wasm import resolve_wasm_python_module

    return resolve_wasm_python_module(config) is not None
