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

"""Shell completion generation."""

from __future__ import annotations

from pysymex.cli.output import print_cli_error
from pysymex.logger import get_logger

logger = get_logger(__name__)


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
    opts="--version --help scan analyze verify benchmark check"

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--version --help --format --output --max-paths --timeout --verbose --workers --recursive --auto --no-sandbox --reproduce" -- ${cur}) )
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
        '(--no-sandbox)--no-sandbox[Compile bytecode in-process]' \\
        '1: :->command' \\
        '*:: :->args'

    case "$state" in
        command)
            _values 'commands' 'scan' 'analyze' 'verify' 'benchmark' 'check'
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
complete -c pysymex -l auto -d "Auto-tune configuration"
complete -c pysymex -l no-sandbox -d "Compile bytecode in-process"
complete -c pysymex -l reproduce -d "Generate reproduction scripts"

# Commands
complete -c pysymex -n "__fish_use_subcommand" -a "scan" -d "Scan file or directory"
complete -c pysymex -n "__fish_use_subcommand" -a "analyze" -d "Analyze specific function"
complete -c pysymex -n "__fish_use_subcommand" -a "verify" -d "Verify contracts"
complete -c pysymex -n "__fish_use_subcommand" -a "benchmark" -d "Run benchmark suite"
complete -c pysymex -n "__fish_use_subcommand" -a "check" -d "CI-friendly severity-gated scan"

# File completion for scan and analyze
complete -c pysymex -n "__fish_seen_subcommand_from scan analyze" -a "(__fish_complete_suffix .py)"
""",
    }

    if shell in completions:
        print(completions[shell])
        return 0
    else:
        logger.warning("Unknown shell requested for completion generation: %s", shell)
        print_cli_error(f"Unknown shell: {shell}")
        return 1


__all__ = ["generate_completion"]
