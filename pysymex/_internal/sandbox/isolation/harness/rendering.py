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

"""Grouped sandbox harness rendering entrypoints."""

from __future__ import annotations

from pysymex._internal.sandbox.isolation.harness.audit import HarnessAudit
from pysymex._internal.sandbox.isolation.harness.bootstrap import HarnessBootstrap
from pysymex._internal.sandbox.isolation.harness.execution import HarnessExecution
from pysymex._internal.sandbox.isolation.harness.validation import HarnessSource


class HarnessRender:
    """Namespace for generated sandbox harness source fragments."""

    bootstrap = staticmethod(HarnessBootstrap.render)
    load_source = staticmethod(HarnessSource.load)
    compile = staticmethod(HarnessAudit.compile)
    execution = staticmethod(HarnessExecution.render)
