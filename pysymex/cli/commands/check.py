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

"""CI check CLI command."""

from __future__ import annotations

import argparse
from typing import cast

from pysymex.cli.commands.shared import RunCiCheckProtocol

_Namespace = argparse.Namespace


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
    run_ci_check_fn = cast("RunCiCheckProtocol", run_ci_check)
    return run_ci_check_fn(
        files=args.paths,
        fail_on=fail_on,
        sarif_output=getattr(args, "sarif", None),
    )


__all__ = ["cmd_check"]
