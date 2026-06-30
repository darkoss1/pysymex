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

from pysymex._internal.cli.commands.registry import command_names, iter_command_specs
from pysymex._internal.cli.output import CliOutput
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)


def _bash_completion() -> str:
    command_words = " ".join(command_names())
    return """
_pysymex_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--version --help __COMMAND_WORDS__"

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "--version --help --format --output --max-paths --max-depth --timeout --verbose --workers --no-sandbox --profile --profile-mode --profile-sample-interval-ms --profile-output-dir --profile-baseline --reproduce" -- ${cur}) )
        return 0
    fi

    if [[ ${prev} == "--format" ]]; then
        COMPREPLY=( $(compgen -W "text json sarif html markdown" -- ${cur}) )
        return 0
    fi

    if [[ ${prev} == "--profile-mode" ]]; then
        COMPREPLY=( $(compgen -W "sample cprofile" -- ${cur}) )
        return 0
    fi

    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}
complete -F _pysymex_completion pysymex
""".replace("__COMMAND_WORDS__", command_words)


def _zsh_completion() -> str:
    zsh_commands = " ".join(f"'{spec.name}[{spec.help}]'" for spec in iter_command_specs())
    return """
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
        '(--max-depth)--max-depth[Max symbolic step depth per path]:depth:' \\
        '(--timeout)--timeout[Timeout in seconds]:timeout:' \\
        '(--profile)--profile[Enable developer profiling]' \\
        '(--profile-output-dir)--profile-output-dir[Profile artifact directory]:directory:_files -/' \\
        '(--profile-baseline)--profile-baseline[Prior profile JSON]:file:_files' \\
        '(-v --verbose)'{-v,--verbose}'[Verbose output]' \\
        '(--no-sandbox)--no-sandbox[Compile bytecode in-process]' \\
        '1: :->command' \\
        '*:: :->args'

    case "$state" in
        command)
            _values 'commands' __ZSH_COMMANDS__
            ;;
        args)
            case "$line[1]" in
                scan)
                    _files -g "*.py"
                    ;;
            esac
            ;;
    esac
}

_pysymex "$@"
""".replace("__ZSH_COMMANDS__", zsh_commands)


def _fish_completion() -> str:
    fish_commands = "\n".join(
        f'complete -c pysymex -n "__fish_use_subcommand" -a "{spec.name}" -d "{spec.help}"'
        for spec in iter_command_specs()
    )
    return """
# Fish completion for pysymex

complete -c pysymex -f

# Options
complete -c pysymex -s v -l version -d "Show version"
complete -c pysymex -s h -l help -d "Show help"
complete -c pysymex -l format -a "text json sarif html markdown" -d "Output format"
complete -c pysymex -s o -l output -r -d "Output file"
complete -c pysymex -l max-paths -r -d "Max paths"
complete -c pysymex -l max-depth -r -d "Max symbolic step depth"
complete -c pysymex -l timeout -r -d "Timeout in seconds"
complete -c pysymex -l profile -d "Enable developer profiling"
complete -c pysymex -l profile-mode -a "sample cprofile" -d "Profiler backend"
complete -c pysymex -l profile-sample-interval-ms -r -d "Sampling interval in milliseconds"
complete -c pysymex -l profile-output-dir -r -d "Profile artifact directory"
complete -c pysymex -l profile-baseline -r -d "Prior profile JSON"
complete -c pysymex -s v -l verbose -d "Verbose output"
complete -c pysymex -l auto -d "Auto-tune configuration"
complete -c pysymex -l no-sandbox -d "Compile bytecode in-process"
complete -c pysymex -l reproduce -d "Generate reproduction scripts"

# Commands
__FISH_COMMANDS__

# File completion for scan
complete -c pysymex -n "__fish_seen_subcommand_from scan" -a "(__fish_complete_suffix .py)"
""".replace("__FISH_COMMANDS__", fish_commands)


def generate_completion(shell: str) -> int:
    """Generate a shell completion script and print it to stdout.

    Args:
        shell: Target shell (``bash``, ``zsh``, or ``fish``).

    Returns:
        ``0`` on success, ``1`` for unknown shell.

    """
    completions = {
        "bash": _bash_completion,
        "zsh": _zsh_completion,
        "fish": _fish_completion,
    }

    if shell in completions:
        CliOutput.safe_print(completions[shell]().rstrip())
        return 0
    logger.warning("Unknown shell requested for completion generation: %s", shell)
    CliOutput.error(f"Unknown shell: {shell}")
    return 1
