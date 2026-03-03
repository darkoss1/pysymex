"""Non-scan CLI commands for PySyMex (analyze, benchmark, verify, etc.)."""

from __future__ import annotations


import argparse

import logging

import sys

from pathlib import Path

from typing import Any

_Namespace = argparse.Namespace

logger = logging.getLogger(__name__)


def cmd_analyze(args: _Namespace) -> int:
    """Execute analyze command for single function."""

    from pysymex.api import analyze_file

    from pysymex.reporting.formatters import format_result

    filepath = Path(args.file)

    if not filepath.exists():
        print(f"\u274c Error: File not found: {filepath}", file=sys.stderr)

        return 1

    symbolic_args: dict[str, str] = {}

    if args.args:
        for arg in args.args:
            if ":" in arg:
                name, type_hint = arg.split(":", 1)

                symbolic_args[name.strip()] = type_hint.strip()

    if args.verbose:
        print(f"\U0001f50d Analyzing {args.function}() in {filepath}")

    try:
        result = analyze_file(
            filepath=filepath,
            function_name=args.function,
            symbolic_args=symbolic_args,
            max_paths=args.max_paths,
            timeout=args.timeout,
            verbose=args.verbose,
        )

        output = format_result(result, args.format)

        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")

            if args.verbose:
                print(f"\U0001f4c4 Report saved to: {args.output}")

        else:
            print(output)

        return 1 if result.has_issues() else 0

    except (ValueError, TypeError, SyntaxError, OSError) as e:
        print(f"\u274c Error analyzing {filepath}: {e}", file=sys.stderr)

        return 1


def cmd_benchmark(args: _Namespace) -> int:
    """Execute benchmark command."""

    from pysymex.benchmarks import run_benchmarks

    output_path = Path(args.output) if args.output else None

    baseline_path = Path(args.baseline) if args.baseline else None

    try:
        return run_benchmarks(
            output_path=output_path,
            baseline_path=baseline_path,
            format=args.format,
            iterations=args.iterations,
        )

    except Exception as e:
        print(f"\u274c Error running benchmarks: {e}", file=sys.stderr)

        return 1


def generate_completion(shell: str) -> int:
    """Generate shell completion script."""

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
complete -F _pysymex_completion PySyMex
""",
        "zsh": """
#compdef PySyMex

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
# Fish completion for PySyMex

complete -c PySyMex -f

# Options
complete -c PySyMex -s v -l version -d "Show version"
complete -c PySyMex -s h -l help -d "Show help"
complete -c PySyMex -l format -a "text json sarif html markdown" -d "Output format"
complete -c PySyMex -s o -l output -r -d "Output file"
complete -c PySyMex -l max-paths -r -d "Max paths"
complete -c PySyMex -l timeout -r -d "Timeout in seconds"
complete -c PySyMex -s v -l verbose -d "Verbose output"
complete -c PySyMex -s r -l recursive -d "Recursive scan"
complete -c PySyMex -l watch -d "Watch for changes"
complete -c PySyMex -l auto -d "Auto-tune configuration"
complete -c PySyMex -l reproduce -d "Generate reproduction scripts"

# Commands
complete -c PySyMex -n "__fish_use_subcommand" -a "scan" -d "Scan file or directory"
complete -c PySyMex -n "__fish_use_subcommand" -a "analyze" -d "Analyze specific function"
complete -c PySyMex -n "__fish_use_subcommand" -a "verify" -d "Verify contracts"
complete -c PySyMex -n "__fish_use_subcommand" -a "concolic" -d "Concolic test generation"
complete -c PySyMex -n "__fish_use_subcommand" -a "benchmark" -d "Run benchmark suite"

# File completion for scan and analyze
complete -c PySyMex -n "__fish_seen_subcommand_from scan analyze" -a "(__fish_complete_suffix .py)"
""",
    }

    if shell in completions:
        print(completions[shell])

        return 0

    else:
        print(f"Unknown shell: {shell}", file=sys.stderr)

        return 1


def cmd_check(args: _Namespace) -> int:
    """Execute CI-friendly check command."""

    from pysymex.ci import run_ci_check

    from pysymex.reporting.sarif import Severity

    severity_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }

    fail_on = severity_map.get(args.fail_on, Severity.HIGH)

    return run_ci_check(
        files=args.paths,
        fail_on=fail_on,
        sarif_output=getattr(args, "sarif", None),
    )


def cmd_verify(args: _Namespace) -> int:
    """Execute verify command for contracts.

    Uses both ContractAnalyzer (static Z3 checking) and VerifiedExecutor
    (symbolic execution with contract/arithmetic/termination verification).
    """

    from pysymex.analysis.contracts import ContractAnalyzer

    filepath = Path(args.file)

    if not filepath.exists():
        print(f"\u274c Error: File not found: {filepath}", file=sys.stderr)

        return 1

    print(
        "\u26a0\ufe0f  EXPERIMENTAL FEATURE: Contract verification is in preview.", file=sys.stderr
    )

    print("    Results may be incomplete or inaccurate.\n", file=sys.stderr)

    try:
        import builtins

        from pysymex.security import create_sandbox_namespace, get_safe_builtins

        source = filepath.read_text(encoding="utf-8")

        compiled = compile(source, str(filepath), "exec")

        safe_builtins = get_safe_builtins()

        safe_builtins["__import__"] = builtins.__import__

        namespace = create_sandbox_namespace(allow_builtins=False)

        namespace["__builtins__"] = safe_builtins

        namespace["__name__"] = "__main__"

        exec(compiled, namespace)

        analyzer = ContractAnalyzer()

        verified_executor_cls = None

        VerifiedExecutionConfig: Any = None

        try:
            from pysymex.execution.verified_executor import (
                VerifiedExecutionConfig,
                VerifiedExecutor,
            )

            verified_executor_cls = VerifiedExecutor

        except Exception:
            logger.debug("Failed to import VerifiedExecutor", exc_info=True)

        if args.function:
            if args.function not in namespace:
                print(f"\u274c Error: Function '{args.function}' not found", file=sys.stderr)

                return 1

            func = namespace[args.function]

            report = analyzer.analyze_function(func)

            print(report.format())

            if verified_executor_cls is not None:
                _run_verified_execution(func, args, verified_executor_cls, VerifiedExecutionConfig)

            return 1 if report.has_violations else 0

        else:
            has_violations = False

            for obj in namespace.values():
                if callable(obj) and hasattr(obj, "__contract__"):
                    if args.verbose:
                        print(f"\U0001f50d Verifying {obj.__name__}...")

                    report = analyzer.analyze_function(obj)

                    print(report.format())

                    if report.has_violations:
                        has_violations = True

                    if verified_executor_cls is not None:
                        _run_verified_execution(
                            obj, args, verified_executor_cls, VerifiedExecutionConfig
                        )

            return 1 if has_violations else 0

    except Exception as e:
        print(f"\u274c Error verifying {filepath}: {e}", file=sys.stderr)

        return 1


def _run_verified_execution(
    func: Any, args: _Namespace, executor_cls: type[Any], config_cls: type[Any]
) -> None:
    """Run VerifiedExecutor on a function and print additional findings."""

    try:
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
                status = result.termination_proof.status.name

                msg = result.termination_proof.message

                print(f"  Termination: {status} - {msg}")

            if result.arithmetic_issues:
                print(f"  Arithmetic issues: {len(result.arithmetic_issues)}")

                for ai in result.arithmetic_issues:
                    print(f"    - {ai.format().strip()}")

            if result.contract_issues:
                for ci in result.contract_issues:
                    print(f"    - {ci.format().strip()}")

            print(
                f"  Paths: {result.paths_explored} explored, " f"{result.paths_completed} completed"
            )

    except Exception as e:
        if getattr(args, "verbose", False):
            print(f"  (VerifiedExecutor: {e})", file=sys.stderr)


def cmd_concolic(args: _Namespace) -> int:
    """Execute concolic command for test generation."""

    from pysymex.analysis.concolic import ConcolicExecutor

    filepath = Path(args.file)

    if not filepath.exists():
        print(f"\u274c Error: File not found: {filepath}", file=sys.stderr)

        return 1

    print("\u26a0\ufe0f  EXPERIMENTAL FEATURE: Concolic execution is in preview.", file=sys.stderr)

    print("    Path exploration heuristics are under development.\n", file=sys.stderr)

    try:
        import builtins

        from pysymex.security import create_sandbox_namespace, get_safe_builtins

        source = filepath.read_text(encoding="utf-8")

        compiled = compile(source, str(filepath), "exec")

        safe_builtins = get_safe_builtins()

        safe_builtins["__import__"] = builtins.__import__

        namespace = create_sandbox_namespace(allow_builtins=False)

        namespace["__builtins__"] = safe_builtins

        namespace["__name__"] = "__main__"

        exec(compiled, namespace)

        if args.function not in namespace:
            print(f"\u274c Error: Function '{args.function}' not found", file=sys.stderr)

            return 1

        func = namespace[args.function]

        executor = ConcolicExecutor(max_iterations=args.iterations)

        if args.verbose:
            print(f"\U0001f50d Running concolic execution on {args.function}...")

        result = executor.execute(func)

        print(result.format_summary())

        failing = result.get_failing_inputs()

        if failing:
            print(f"\n\u274c Found {len(failing)} failing inputs!")

            return 1

        return 0

    except Exception as e:
        print(f"\u274c Error in concolic execution for {filepath}: {e}", file=sys.stderr)

        return 1
