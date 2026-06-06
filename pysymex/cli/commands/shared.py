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
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from pysymex.cli.output import print_cli_warning

_Namespace = argparse.Namespace


class RunCiCheckProtocol(Protocol):
    """Protocol defining the interface for running CI safety checks on specified files."""

    def __call__(
        self,
        *,
        files: list[str] | tuple[str, ...] | object,
        fail_on: object,
        sarif_output: str | None,
    ) -> int:
        """Execute the CI check workflow.

        Args:
            files (list[str] | tuple[str, ...] | object): A collection of filepaths to analyze.
            fail_on (object): Criteria or issue severity thresholds that should trigger a failure.
            sarif_output (str | None): Optional filepath to write a SARIF format report.

        Returns:
            int: Exit code of the CI check (zero for success, non-zero for failure).
        """
        ...


class VerifiedConfigFactory(Protocol):
    """Protocol defining the interface for creating verified execution configuration objects."""

    def __call__(self, **kwargs: object) -> object:
        """Create a verified configuration object from the provided keyword arguments.

        Args:
            **kwargs (object): Arbitrary configuration options to forward.

        Returns:
            object: A constructed execution configuration instance.
        """
        ...


class _TerminationProofProtocol(Protocol):
    """Protocol defining the structure of a termination proof result.

    Attributes:
        status (object): Status code of the termination proof.
        message (str): Explanatory message regarding the termination proof status.
    """

    status: object
    message: str


class VerifiedExecutionResultProtocol(Protocol):
    """Protocol defining the interface for the result of a formally verified symbolic execution.

    Attributes:
        function_name (str): The name of the verified function.
        paths_explored (int): Total number of paths explored during analysis.
        paths_completed (int): Number of execution paths that ran to completion.
        issues (list[object]): Discovered general execution issues.
        arithmetic_issues (list[object]): Discovered arithmetic-related issues (e.g. overflow, div by zero).
        contract_issues (list[object]): Discovered contract safety issues.
        termination_proof (_TerminationProofProtocol | None): Termination proof result, if verification completed.
        degraded_passes (list[str]): List of analysis passes that were degraded or skipped.
    """

    function_name: str
    paths_explored: int
    paths_completed: int
    issues: list[object]
    arithmetic_issues: list[object]
    contract_issues: list[object]
    termination_proof: _TerminationProofProtocol | None
    degraded_passes: list[str]


class _VerifiedExecutorProtocol(Protocol):
    """Protocol defining the interface for a verified symbolic executor."""

    def execute_function(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
    ) -> VerifiedExecutionResultProtocol:
        """Execute symbolic analysis and formal verification on a target function.

        Args:
            func (Callable[..., object]): The Python function/callable to verify.
            symbolic_args (dict[str, str] | None): Declared symbolic argument types.

        Returns:
            VerifiedExecutionResultProtocol: Detailed results of the symbolic execution and verification.
        """
        ...


class VerifiedExecutorFactory(Protocol):
    """Protocol defining the interface for a factory that instantiates verified symbolic executors."""

    def __call__(self, config: object) -> _VerifiedExecutorProtocol:
        """Instantiate a verified executor with the given configuration object.

        Args:
            config (object): The configuration settings to initialize the executor with.

        Returns:
            _VerifiedExecutorProtocol: An initialized verified executor instance.
        """
        ...


def load_function_for_cli(
    filepath: Path,
    function_name: str,
) -> Callable[..., object]:
    """Load a single target function through the sandbox bridge."""
    from pysymex.sandbox.bridge.module import extract_module

    module_blob = extract_module(filepath.read_bytes(), str(filepath))
    return module_blob.get_function(function_name)


def run_cli_command_sandboxed(command: str, args: _Namespace) -> int:
    """Dispatch CLI commands through the sandbox-aware execution path."""
    sandbox_args = argparse.Namespace(**vars(args))
    sandbox_args._sandbox_dispatch = True

    if command == "verify":
        from pysymex.cli.commands.verify import cmd_verify

        return cmd_verify(sandbox_args)

    raise ValueError(f"Unsupported sandboxed command: {command}")


def emit_preview_warning(args: _Namespace, message: str) -> None:
    """Emit an experimental-feature warning once across sandbox redispatch."""
    if getattr(args, "_preview_warning_emitted", False):
        return
    print_cli_warning(message)
    setattr(args, "_preview_warning_emitted", True)


__all__ = [
    "VerifiedConfigFactory",
    "VerifiedExecutionResultProtocol",
    "VerifiedExecutorFactory",
    "load_function_for_cli",
    "run_cli_command_sandboxed",
    "emit_preview_warning",
    "RunCiCheckProtocol",
]
