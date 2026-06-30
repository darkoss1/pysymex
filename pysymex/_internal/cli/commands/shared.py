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

"""Shared helpers for non-scan CLI commands."""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Protocol

from pysymex._internal.cli.output import CliOutput

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

_Namespace = argparse.Namespace


class _TerminationProofProtocol(Protocol):
    """Protocol defining the structure of a termination proof result.

    The CLI only reads termination status and message for formatting.
    """

    @property
    def status(self) -> object:
        """Status code of the termination proof."""
        ...

    @property
    def message(self) -> str:
        """Explanatory message for the termination proof status."""
        ...


class ExecutionResultProtocol(Protocol):
    """Protocol defining the interface for the result of a formally verified symbolic execution.

    The CLI formatter and exit-code path only read these fields, so the protocol exposes
    covariant read-only views instead of mutable list attributes.
    """

    @property
    def function_name(self) -> str:
        """Name of the verified function."""
        ...

    @property
    def paths_explored(self) -> int:
        """Total number of paths explored during analysis."""
        ...

    @property
    def paths_completed(self) -> int:
        """Number of execution paths that ran to completion."""
        ...

    @property
    def issues(self) -> Sequence[object]:
        """Discovered general execution issues."""
        ...

    @property
    def arithmetic_issues(self) -> Sequence[object]:
        """Discovered arithmetic-related issues."""
        ...

    @property
    def contract_issues(self) -> Sequence[object]:
        """Discovered contract safety issues."""
        ...

    @property
    def termination_proof(self) -> _TerminationProofProtocol | None:
        """Termination proof result, if verification completed."""
        ...

    @property
    def degraded_passes(self) -> Sequence[str]:
        """Analysis passes that were degraded or skipped."""
        ...


def load_function_for_cli(
    filepath: Path,
    function_name: str,
) -> Callable[..., object]:
    """Load a single target function through the sandbox bridge."""
    from pysymex._internal.sandbox.bridge.module.extract import extract_module

    module_blob = extract_module(filepath.read_bytes(), str(filepath))
    return module_blob.get_function(function_name)


def run_cli_command_sandboxed(command: str, args: _Namespace) -> int:
    """Dispatch CLI commands through the sandbox-aware execution path."""
    sandbox_args = argparse.Namespace(**vars(args))
    sandbox_args.command = command
    sandbox_args._sandbox_dispatch = True

    from pysymex._internal.cli.commands.registry import dispatch_command

    result = dispatch_command(sandbox_args)
    if result is None:
        msg = f"Unsupported sandboxed command: {command}"
        raise ValueError(msg)
    return result


def emit_preview_warning(args: _Namespace, message: str) -> None:
    """Emit an experimental-feature warning once across sandbox redispatch."""
    if getattr(args, "_preview_warning_emitted", False):
        return
    CliOutput.warning(message)
    args._preview_warning_emitted = True
