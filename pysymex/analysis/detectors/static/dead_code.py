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

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from pysymex.analysis.detectors.types import DetectionContext, Issue, IssueKind, StaticDetector


class DeadCodeDetector(StaticDetector):
    """
    Detector for dead/unreachable code.
    Finds code that can never execute.
    """

    def issue_kind(self) -> IssueKind:
        return IssueKind.DEAD_CODE

    def should_check(self, ctx: DetectionContext) -> bool:
        return ctx.flow_context is not None

    def check(self, ctx: DetectionContext) -> Issue | None:
        """Check."""
        if ctx.flow_context is None:
            return None
        if ctx.flow_context.block:
            block_id = ctx.flow_context.block.id
            if not ctx.flow_context.analyzer.cfg.is_reachable(block_id):
                return self.create_issue(
                    ctx,
                    message="Unreachable code",
                    confidence=0.9,
                    explanation="This code can never be executed.",
                )
        return None
