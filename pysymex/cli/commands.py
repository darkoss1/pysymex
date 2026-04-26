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

"""Non-scan CLI commands for pysymex (analyze, benchmark, verify, etc.)."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

_Namespace = argparse.Namespace
logger = logging.getLogger(__name__)


def _load_namespace_for_cli(filepath: Path, *, use_sandbox: bool) -> dict[str, object]:
    """Load a Python module namespace for CLI commands.

    When ``use_sandbox`` is enabled, source is compiled through the strict
    sandbox bridge and executed with hardened builtins.
    """
    if use_sandbox:
        from pysymex.sandbox.bridge import extract_bytecode
        from pysymex.sandbox.execution import get_hardened_builtins

        bytecode_blob = extract_bytecode(
            filepath.read_bytes(),
            str(filepath),
            sandbox_config={"allow_compat_fallback": True},
        )
        compiled = bytecode_blob.reconstruct()
        sandbox_namespace: dict[str, object] = {
            "__builtins__": get_hardened_builtins(),
            "__name__": "__main__",
            "__file__": str(filepath),
        }
        exec(compiled, sandbox_namespace)
        return sandbox_namespace

    # When sandbox is disabled, use normal exec with full builtins
    source = filepath.read_text(encoding="utf-8")
    namespace: dict[str, object] = {
        "__builtins__": __builtins__,
        "__name__": "__main__",
        "__file__": str(filepath),
    }
    exec(compile(source, str(filepath), "exec"), namespace)
    return namespace


def _run_cli_command_sandboxed(command: str, args: _Namespace) -> int:
    """Dispatch CLI commands through the sandbox-aware execution path."""
    sandbox_args = argparse.Namespace(**vars(args))
    sandbox_args._sandbox_dispatch = True
    # Don't override the original sandbox flag - respect user's choice

    if command == "verify":
        return cmd_verify(sandbox_args)
    if command == "concolic":
        return cmd_concolic(sandbox_args)

    raise ValueError(f"Unsupported sandboxed command: {command}")


class _RunCiCheckProtocol(Protocol):
    def __call__(
        self,
        *,
        files: list[str] | tuple[str, ...] | object,
        fail_on: object,
        sarif_output: str | None,
    ) -> int: ...


class _VerifiedConfigFactory(Protocol):
    def __call__(self, **kwargs: object) -> object: ...


class _TerminationProofProtocol(Protocol):
    status: object
    message: str


class _VerifiedExecutionResultProtocol(Protocol):
    function_name: str
    paths_explored: int
    paths_completed: int
    arithmetic_issues: list[object]
    contract_issues: list[object]
    termination_proof: _TerminationProofProtocol | None


class _VerifiedExecutorProtocol(Protocol):
    def execute_function(self, func: Callable[..., object]) -> _VerifiedExecutionResultProtocol: ...


class _VerifiedExecutorFactory(Protocol):
    def __call__(self, config: object) -> _VerifiedExecutorProtocol: ...


def cmd_analyze(args: _Namespace) -> int:
    """Execute the ``analyze`` sub-command for a single function.

    Args:
        args: Parsed CLI namespace with ``file``, ``function``,
            ``args``, ``format``, ``output``, ``max_paths``,
            ``timeout``, ``verbose``, and ``stats`` attributes.

    Returns:
        ``1`` if issues were found, ``0`` otherwise.
    """
    from pysymex.api import analyze_file
    from pysymex.cli.reporter import ConsoleScanReporter
    from pysymex.reporting.formatters import format_result

    filepath = Path(args.file)
    if not filepath.exists():
        print(f"[X] Error: File not found: {filepath}", file=sys.stderr)
        return 1
    symbolic_args: dict[str, str] = {}
    if args.args:
        for arg in args.args:
            if ":" in arg:
                name, type_hint = arg.split(":", 1)
                symbolic_args[name.strip()] = type_hint.strip()

    show_stats = getattr(args, "stats", False)
    reporter = ConsoleScanReporter(show_stats=show_stats) if args.verbose else None

    if args.verbose:
        print(f"[SCAN] Analyzing {args.function}() in {filepath}")
    try:
        result = analyze_file(
            filepath=filepath,
            function_name=args.function,
            symbolic_args=symbolic_args,
            max_paths=args.max_paths,
            timeout=args.timeout,
            verbose=args.verbose,
            reporter=reporter,
        )
        output = format_result(result, args.format)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            if args.verbose:
                print(f"[REPORT] Report saved to: {args.output}")
        else:
            print(output)
        return 1 if result.has_issues() else 0
    except (ValueError, TypeError, SyntaxError, OSError) as e:
        print(f"[X] Error analyzing {filepath}: {e}", file=sys.stderr)
        return 1


def cmd_benchmark(args: _Namespace) -> int:
    """Execute the ``benchmark`` sub-command.

    Runs the built-in benchmark suite and writes results in the
    requested format.

    Args:
        args: Parsed CLI namespace with ``output``, ``baseline``,
            ``format``, and ``iterations`` attributes.

    Returns:
        ``0`` on success, ``1`` if regressions are detected.
    """
    from pysymex.benchmarks import run_benchmarks

    output_path = Path(args.output) if args.output else None
    baseline_path = Path(args.baseline) if args.baseline else None
    run_benchmarks_fn = cast("Callable[..., int]", run_benchmarks)
    try:
        return run_benchmarks_fn(
            output_path=output_path,
            baseline_path=baseline_path,
            format=args.format,
            iterations=args.iterations,
            case_name=getattr(args, "case", None),
        )
    except Exception as e:
        print(f"[X] Error running benchmarks: {e}", file=sys.stderr)
        return 1


def generate_completion(shell: str) -> int:
    """Generate a shell completion script and print it to stdout.

    Args:
        shell: Target shell (``bash``, ``zsh``, or ``fish``).

    Returns:
        ``0`` on success, ``1`` for unknown shell.
    """
    completions = {
        "bash": """
_pysymex_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--version --help scan analyze verify concolic benchmark"

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--version --help --format --output --max-paths --timeout --verbose --workers --recursive --watch --auto --reproduce" -- ${cur}) )
        return 0
    fi

    if [[ ${prev} == "--format" ]]; then
        COMPREPLY=( $(compgen -W "text json sarif html markdown" -- ${cur}) )
        return 0
    fi

    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}
complete -F _pysymex_completion pysymex
""",
        "zsh": """
#compdef pysymex

_pysymex() {
    local curcontext="$curcontext" state line
    typeset -A opt_args

    _arguments -C \\
        '(-v --version)'{-v,--version}'[Show version]' \\
        '(-h --help)'{-h,--help}'[Show help]' \\
        '(--format)--format[Output format]:format:(text json sarif html markdown)' \\
        '(-o --output)'{-o,--output}'[Output file]:file:_files' \\
        '(--max-paths)--max-paths[Max paths to explore]:paths:' \\
        '(--timeout)--timeout[Timeout in seconds]:timeout:' \\
        '(-v --verbose)'{-v,--verbose}'[Verbose output]' \\
        '(-r --recursive)'{-r,--recursive}'[Recursive scan]' \\
        '(--watch)--watch[Watch for changes]' \\
        '1: :->command' \\
        '*:: :->args'

    case "$state" in
        command)
            _values 'commands' 'scan' 'analyze' 'verify' 'concolic' 'benchmark'
            ;;
        args)
            case "$line[1]" in
                scan)
                    _files -g "*.py"
                    ;;
                analyze)
                    _files -g "*.py"
                    ;;
            esac
            ;;
    esac
}

_pysymex "$@"
""",
        "fish": """
# Fish completion for pysymex

complete -c pysymex -f

# Options
complete -c pysymex -s v -l version -d "Show version"
complete -c pysymex -s h -l help -d "Show help"
complete -c pysymex -l format -a "text json sarif html markdown" -d "Output format"
complete -c pysymex -s o -l output -r -d "Output file"
complete -c pysymex -l max-paths -r -d "Max paths"
complete -c pysymex -l timeout -r -d "Timeout in seconds"
complete -c pysymex -s v -l verbose -d "Verbose output"
complete -c pysymex -s r -l recursive -d "Recursive scan"
complete -c pysymex -l watch -d "Watch for changes"
complete -c pysymex -l auto -d "Auto-tune configuration"
complete -c pysymex -l reproduce -d "Generate reproduction scripts"

# Commands
complete -c pysymex -n "__fish_use_subcommand" -a "scan" -d "Scan file or directory"
complete -c pysymex -n "__fish_use_subcommand" -a "analyze" -d "Analyze specific function"
complete -c pysymex -n "__fish_use_subcommand" -a "verify" -d "Verify contracts"
complete -c pysymex -n "__fish_use_subcommand" -a "concolic" -d "Concolic test generation"
complete -c pysymex -n "__fish_use_subcommand" -a "benchmark" -d "Run benchmark suite"

# File completion for scan and analyze
complete -c pysymex -n "__fish_seen_subcommand_from scan analyze" -a "(__fish_complete_suffix .py)"
""",
    }

    if shell in completions:
        print(completions[shell])
        return 0
    else:
        print(f"Unknown shell: {shell}", file=sys.stderr)
        return 1


def cmd_check(args: _Namespace) -> int:
    """Execute the CI-friendly ``check`` sub-command.

    Maps ``args.fail_on`` to a :class:`~pysymex.reporting.sarif.Severity`
    and delegates to :func:`pysymex.ci.run_ci_check`.

    Args:
        args: Parsed CLI namespace with ``paths``, ``fail_on``,
            ``sarif``, and ``verbose`` attributes.

    Returns:
        Exit code suitable for CI pipelines.
    """
    from pysymex.ci import run_ci_check
    from pysymex.reporting.sarif import Severity

    severity_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    fail_on = severity_map.get(args.fail_on, Severity.HIGH)
    run_ci_check_fn = cast("_RunCiCheckProtocol", run_ci_check)
    return run_ci_check_fn(
        files=args.paths,
        fail_on=fail_on,
        sarif_output=getattr(args, "sarif", None),
    )


def cmd_verify(args: _Namespace) -> int:
    """Execute verify command for contracts.

    Uses VerifiedExecutor for symbolic execution with full contract verification
    (preconditions, postconditions, invariants, termination).
    """
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"[X] Error: File not found: {filepath}", file=sys.stderr)
        return 1

    print("[!]  EXPERIMENTAL FEATURE: Contract verification is in preview.", file=sys.stderr)
    print("    Results may be incomplete or inaccurate.\n", file=sys.stderr)

    use_sandbox = bool(getattr(args, "sandbox", True))
    # Only dispatch to sandbox path if sandbox is enabled and not already dispatched
    if use_sandbox and not getattr(args, "_sandbox_dispatch", False):
        return _run_cli_command_sandboxed("verify", args)

    try:
        from pysymex.execution.executors.verified import (
            VerifiedExecutionConfig,
            VerifiedExecutor,
        )
    except ImportError:
        print("[X] Error: VerifiedExecutor not available", file=sys.stderr)
        return 1

    try:
        namespace = _load_namespace_for_cli(
            filepath,
            use_sandbox=use_sandbox,
        )

        if args.function:
            if args.function not in namespace:
                print(f"[X] Error: Function '{args.function}' not found", file=sys.stderr)
                return 1
            func_obj = namespace[args.function]
            if not callable(func_obj):
                print(f"[X] Error: '{args.function}' is not callable", file=sys.stderr)
                return 1
            func = func_obj
            _run_verified_execution(
                func,
                args,
                VerifiedExecutor,  # type: ignore[arg-type]  # will be fixed later
                VerifiedExecutionConfig,  # type: ignore[arg-type]  # will be fixed later
            )
            return 0
        else:
            for obj in namespace.values():
                if callable(obj) and hasattr(obj, "__contract__"):
                    fn = obj
                    if args.verbose:
                        print(f"[SCAN] Verifying {fn.__name__}...")
                    _run_verified_execution(
                        fn,
                        args,
                        VerifiedExecutor,  # type: ignore[arg-type]  # will be fixed later
                        VerifiedExecutionConfig,  # type: ignore[arg-type]  # will be fixed later
                    )
            return 0

    except Exception as e:
        print(f"[X] Error verifying {filepath}: {e}", file=sys.stderr)
        return 1


def _run_verified_execution(
    func: Callable[..., object],
    args: _Namespace,
    executor_cls: _VerifiedExecutorFactory,
    config_cls: _VerifiedConfigFactory | None,
) -> object:
    """Run :class:`VerifiedExecutor` on *func* and print findings.

    Called internally by :func:`cmd_verify` to perform symbolic-execution verification.

    Args:
        func: The Python function to verify.
        args: Parsed CLI namespace (used for ``verbose``).
        executor_cls: The ``VerifiedExecutor`` class.
        config_cls: The ``VerifiedExecutionConfig`` class.

    Returns:
        The execution result object.
    """
    try:
        if config_cls is None:
            return False
        config = config_cls(
            check_preconditions=True,
            check_postconditions=True,
            check_termination=True,
            check_overflow=True,
            check_division_safety=True,
            verbose=getattr(args, "verbose", False),
            max_paths=200,
            max_iterations=2000,
        )
        executor = executor_cls(config)
        result = executor.execute_function(func)

        has_findings = (
            result.contract_issues or result.arithmetic_issues or result.termination_proof
        )
        if has_findings:
            print(f"\n  --- Verified Execution: {result.function_name} ---")
            if result.termination_proof:
                status_obj = result.termination_proof.status
                status_name = getattr(status_obj, "name", None)
                status = status_name if isinstance(status_name, str) else str(status_obj)
                msg = result.termination_proof.message
                print(f"  Termination: {status} - {msg}")
            if result.arithmetic_issues:
                print(f"  Arithmetic issues: {len(result.arithmetic_issues)}")
                for ai in result.arithmetic_issues:
                    format_fn = getattr(ai, "format", None)
                    if callable(format_fn):
                        print(f"    - {str(format_fn()).strip()}")
                    else:
                        print(f"    - {ai}")
            if result.contract_issues:
                for ci in result.contract_issues:
                    format_fn = getattr(ci, "format", None)
                    if callable(format_fn):
                        print(f"    - {str(format_fn()).strip()}")
                    else:
                        print(f"    - {ci}")
            print(f"  Paths: {result.paths_explored} explored, {result.paths_completed} completed")
            return bool(result.contract_issues or result.arithmetic_issues)
        return False
    except Exception as e:
        if getattr(args, "verbose", False):
            print(f"  (VerifiedExecutor: {e})", file=sys.stderr)
        return False


def cmd_concolic(args: _Namespace) -> int:
    """Execute the ``concolic`` sub-command for test generation.

    Runs concolic execution on the specified function to discover
    crashing inputs.

    Args:
        args: Parsed CLI namespace with ``file``, ``function``,
            ``iterations``, and ``verbose`` attributes.

    Returns:
        ``1`` if failing inputs were found, ``0`` otherwise.
    """
    from pysymex.analysis.concolic import ConcolicExecutor

    filepath = Path(args.file)
    if not filepath.exists():
        print(f"[X] Error: File not found: {filepath}", file=sys.stderr)
        return 1

    if getattr(args, "sandbox", True) and not getattr(args, "_sandbox_dispatch", False):
        return _run_cli_command_sandboxed("concolic", args)

    print("[!]  EXPERIMENTAL FEATURE: Concolic execution is in preview.", file=sys.stderr)
    print("    Path exploration heuristics are under development.\n", file=sys.stderr)

    try:
        namespace = _load_namespace_for_cli(
            filepath,
            use_sandbox=bool(getattr(args, "sandbox", True)),
        )

        if args.function not in namespace:
            print(f"[X] Error: Function '{args.function}' not found", file=sys.stderr)
            return 1
        func_obj = namespace[args.function]
        if not callable(func_obj):
            print(f"[X] Error: '{args.function}' is not callable", file=sys.stderr)
            return 1
        func = func_obj

        executor = ConcolicExecutor(max_iterations=args.iterations)
        if args.verbose:
            print(f"[SCAN] Running concolic execution on {args.function}...")

        result = executor.execute(func)
        print(result.format_summary())

        failing = result.get_failing_inputs()
        if failing:
            print(f"\n[X] Found {len(failing)} failing inputs!")
            return 1
        return 0

    except Exception as e:
        print(f"[X] Error in concolic execution for {filepath}: {e}", file=sys.stderr)
        return 1
