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

"""Contract verification CLI command."""

from __future__ import annotations

import argparse
import time
from typing import TYPE_CHECKING, cast

from pysymex._internal.cli.commands.shared import (
    ExecutionResultProtocol,
    emit_preview_warning,
    load_function_for_cli,
    run_cli_command_sandboxed,
)
from pysymex._internal.cli.commands.validation import symbolic_arg_spec, symbolic_args_from_specs
from pysymex._internal.cli.output import CliOutput
from pysymex._internal.config.defaults import DEFAULT_OUTPUT_FORMAT, SCAN_OUTPUT_FORMAT_CHOICES
from pysymex._internal.logging.root import get_logger
from pysymex._internal.pathing import normalize_input_path

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.cli.commands.registry import Subparsers

_Namespace = argparse.Namespace
logger = get_logger(__name__)
emit_cli_output = CliOutput.emit


def add_verify_parser(subparsers: Subparsers) -> None:
    """Register the ``verify`` sub-command parser."""
    verify_parser = subparsers.add_parser(
        "contracts",
        prog="pysymex contracts",
        usage="pysymex contracts PATH [-f NAME] [options]",
        help="Verify contract-decorated functions",
        description=(
            "Verify contract-decorated functions in a Python file or directory. "
            "If no function is specified via -f/--function, all functions "
            "with contract decorators in the target file(s) will be auto-discovered and verified."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pysymex contracts src/contracts.py\n"
            "  pysymex contracts src/project_dir/\n"
            "  pysymex contracts src/contracts.py -f bounded_divide\n"
            "  pysymex contracts src/contracts.py -f bounded_divide --args x:int y:int\n"
            "  pysymex contracts src/contracts.py --format json -o verify.json"
        ),
    )
    verify_parser.add_argument(
        "file", metavar="PATH", help="Python file or directory with contracts"
    )
    verify_parser.add_argument(
        "-f",
        "--function",
        metavar="NAME",
        help="Function to verify; optional if the file has contract-decorated functions",
    )
    verify_parser.add_argument(
        "--args",
        nargs="*",
        type=symbolic_arg_spec,
        metavar="NAME:TYPE",
        help="Symbolic argument hints, for example x:int y:int",
    )
    verify_parser.add_argument(
        "--format",
        choices=SCAN_OUTPUT_FORMAT_CHOICES,
        metavar="FORMAT",
        default=DEFAULT_OUTPUT_FORMAT,
        help="Output format. Choices: text, json, sarif, rich, html, markdown (default: text)",
    )
    verify_parser.add_argument("-o", "--output", help="Write report to file")
    verify_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")


def cmd_verify(args: _Namespace) -> int:
    """Execute verify command for contracts.

    Uses the public verification API for symbolic execution with contract
    verification (preconditions, postconditions, and invariants).
    """
    filepath = normalize_input_path(str(args.file))
    if not filepath.exists():
        logger.warning("Verify command target not found: %s", filepath)
        CliOutput.error(f"File not found: {filepath}")
        return 1
    try:
        symbolic_args = symbolic_args_from_specs(getattr(args, "args", None))
    except ValueError as e:
        CliOutput.error(str(e))
        return 1
    args._symbolic_args = symbolic_args

    emit_preview_warning(
        args,
        "Contract verification is in preview; results may be incomplete or inaccurate.",
    )

    # Only dispatch to sandbox path if sandbox is enabled and not already dispatched
    if not getattr(args, "_sandbox_dispatch", False):
        return run_cli_command_sandboxed("contracts", args)

    try:
        from pysymex._internal.execution.executors.verified.api import verify as verify_function
    except ImportError:
        logger.warning("Verification API unavailable for verify command", exc_info=True)
        CliOutput.error("Verification API not available")
        return 1

    try:
        start_time = time.time()
        logger.verbose("Verify command started file=%s function=%s", filepath, args.function)

        if filepath.is_dir():
            if args.function:
                CliOutput.error(
                    "Cannot specify function name (-f/--function) when verifying a directory."
                )
                return 1
            from pysymex._internal.scanner.directory.planning import select_directory_files

            selection = select_directory_files(filepath, "**/*.py")
            target_files = list(selection.files)
        else:
            target_files = [filepath]

        results: list[ExecutionResultProtocol] = []
        execution_failed = False
        discovered_any = False

        for file_path in target_files:
            if args.function:
                func = load_function_for_cli(
                    file_path,
                    str(args.function),
                )
                result = _run_verified_execution(
                    func,
                    args,
                    verify_function,
                )
                if result is None:
                    execution_failed = True
                else:
                    results.append(result)
                    discovered_any = True
            else:
                from pysymex._internal.sandbox.bridge.module.extract import extract_module
                from pysymex._internal.contracts.decorator.registry import ContractRegistry

                try:
                    module_blob = extract_module(file_path.read_bytes(), str(file_path))
                except Exception:
                    logger.warning("Failed to extract module from %s", file_path, exc_info=True)
                    execution_failed = True
                    continue

                for name in module_blob.function_names():
                    func = module_blob.get_function(name)
                    if ContractRegistry.get(func) is not None:
                        result = _run_verified_execution(
                            func,
                            args,
                            verify_function,
                        )
                        if result is None:
                            execution_failed = True
                        else:
                            results.append(result)
                            discovered_any = True

        if not discovered_any:
            target_desc = "directory" if filepath.is_dir() else "file"
            CliOutput.error(f"No contract-decorated functions found in the {target_desc}.")
            return 1

        total_findings = sum(
            len(result.issues) + len(result.contract_issues) + len(result.arithmetic_issues)
            for result in results
        )
        analysis_degraded = any(result.degraded_passes for result in results)
        for res in results:
            if int(getattr(res, "contracts_checked", 0)) == 0:
                func_name = getattr(res, "function_name", args.function or "<unknown>")
                CliOutput.warning(
                    f"No contract decorators detected or checked on function '{func_name}'."
                )
        duration = time.time() - start_time

        from pysymex._internal.cli.formatters.registry import get_formatter

        formatter = get_formatter(str(getattr(args, "format", "text")))
        output = formatter.format_verify(results, total_findings, duration)
        emit_cli_output(
            output,
            output_path=getattr(args, "output", None),
            verbose=bool(getattr(args, "verbose", False)),
        )
        return 1 if execution_failed or total_findings > 0 or analysis_degraded else 0

    except Exception as e:
        logger.warning("Verify command failed for %s", filepath, exc_info=True)
        CliOutput.error(f"verifying {filepath}: {e}")
        return 1


def _run_verified_execution(
    func: Callable[..., object],
    args: _Namespace,
    verify_function: Callable[..., ExecutionResultProtocol],
) -> ExecutionResultProtocol | None:
    """Run the public verification API on *func*.

    Called internally by :func:`cmd_verify` to perform symbolic-execution verification.

    Args:
        func: The Python function to verify.
        args: Parsed CLI namespace (used for ``verbose``).
        verify_function: Public verification API callable.

    Returns:
        Verification result, or ``None`` when verification could not run.

    """
    try:
        symbolic_args = cast(
            "dict[str, str] | None",
            getattr(args, "_symbolic_args", None),
        )
        if symbolic_args is None:
            symbolic_args = symbolic_args_from_specs(getattr(args, "args", None))

        return verify_function(
            func,
            symbolic_args=symbolic_args,
            check_preconditions=True,
            check_postconditions=True,
            verbose=getattr(args, "verbose", False),
        )
    except Exception as e:
        logger.warning("Verification API failed for %s", func.__name__, exc_info=True)
        if getattr(args, "verbose", False):
            CliOutput.error(f"verification failed for {func.__name__}: {e}")
        return None
