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

"""Issue event emission behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pydantic import BaseModel

from pysymex.logger import get_logger
from pysymex.tracing.schemas import ConstraintEntry, IssueEvent, TracerConfig
from pysymex.tracing.tracer.helpers import serialize_constraint_entries, serialize_model_excerpt
from pysymex.tracing.z3.serializer import Z3Serializer

if TYPE_CHECKING:
    from pysymex.analysis.detectors.detector.types import Issue
    from pysymex.core.state.record import VMState
    from pysymex.execution.executors.core import SymbolicExecutor
    from pysymex.tracing.schemas import KeyframeEvent


logger = get_logger(__name__)


class TracerIssueMixin:
    """Issue keyframe and issue event emission behavior."""

    if TYPE_CHECKING:
        config: TracerConfig
        _serializer: Z3Serializer

        def _next_seq(self) -> int:
            """Allocate and return the next event sequence number.

            Returns:
                The next sequential integer identifier.
            """
            ...

        def _build_keyframe(
            self,
            state: VMState,
            trigger: str,
            child_path_ids: list[int] | None,
            prune_reason: str | None,
        ) -> KeyframeEvent:
            """Construct a keyframe snapshot representing a point in execution.

            Args:
                state: The current virtual machine state.
                trigger: The event that triggered the keyframe.
                child_path_ids: Child path IDs if the trigger was a fork.
                prune_reason: The reason for pruning if the trigger was prune.

            Returns:
                A populated KeyframeEvent object.
            """
            ...

        def _get_source_line(self, filename: str | None, line_number: int | None) -> str | None:
            """Retrieve the source code text corresponding to a filename and line number.

            Args:
                filename: Path to the target source file, or None to use default.
                line_number: Line number to look up.

            Returns:
                The source code line as a stripped string, or None if not found.
            """
            ...

        def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
            """Write a telemetry event to the trace output buffer.

            Args:
                event: The event payload model to write.
                force_flush: Whether to flush the output file immediately.
            """
            ...

    def on_issue(
        self,
        executor: SymbolicExecutor,
        state: VMState,
        issue: Issue,
    ) -> None:
        """Emit a keyframe + issue event when a bug is detected.

        Args:
            executor: The running executor.
            state:    The VM state at detection time.
            issue:    The :class:`~pysymex.analysis.detectors.detector.types.Issue` object.
        """
        if not self.config.enabled:
            return

        if self.config.keyframe_on_issue:
            kf = self._build_keyframe(
                state=state, trigger="issue", child_path_ids=None, prune_reason=None
            )
            self._write_event(kf, force_flush=False)

        z3_model: dict[str, str] | None = None
        issue_model = getattr(issue, "model", None)
        if issue_model is not None:
            z3_model = serialize_model_excerpt(
                self._serializer,
                issue_model,
                max_vars=30,
                failure_message="Failed to serialize issue Z3 model",
            )
        if z3_model is None:
            ce = getattr(issue, "counterexample", None)
            if ce:
                z3_model = {str(k): str(v) for k, v in ce.items()}

        constraints_at_issue: list[ConstraintEntry] = []
        try:
            pc_val = getattr(state, "pc", 0)
            causality_base = f"path constraint at PC={pc_val}"
            issue_constraints: list[object] = cast(
                "list[object]", getattr(issue, "constraints", None) or []
            )
            constraints_at_issue = serialize_constraint_entries(
                self._serializer,
                issue_constraints,
                causality_base,
                limit=self.config.max_constraint_display,
            )
        except Exception:
            logger.debug("Failed to serialize issue constraints", exc_info=True)

        severity = "HIGH"
        try:
            sev_attr = getattr(issue, "severity", None)
            if sev_attr is not None:
                severity = str(sev_attr.name) if hasattr(sev_attr, "name") else str(sev_attr)
        except Exception:
            logger.debug("Failed to read issue severity", exc_info=True)

        issue_kind = "UNKNOWN"
        try:
            kind_attr = getattr(issue, "kind", None)
            if kind_attr is not None:
                issue_kind = kind_attr.name if hasattr(kind_attr, "name") else str(kind_attr)
        except Exception:
            logger.debug("Failed to read issue kind", exc_info=True)

        detector_name = issue_kind.lower().replace("_", "-")
        try:
            explicit_detector = getattr(issue, "detector_name", None)
            if explicit_detector:
                detector_name = str(explicit_detector)
            elif fn := getattr(issue, "function_name", None):
                detector_name = fn
        except Exception:
            logger.debug("Failed to read issue function name", exc_info=True)

        source_line: int | None = getattr(issue, "line_number", None)

        confidence = 1.0
        likelihood = 1.0

        if hasattr(issue, "confidence"):
            confidence = float(getattr(issue, "confidence", 1.0))
        if hasattr(issue, "likelihood"):
            likelihood = float(getattr(issue, "likelihood", 1.0))

        if confidence == 1.0:
            if issue_kind == "NULL_DEREFERENCE" and "unpack_" in detector_name:
                confidence = 0.4
                likelihood = 0.3
            elif issue_kind == "TYPE_ERROR" and "None" in str(getattr(issue, "message", "")):
                confidence = 0.5

        event = IssueEvent(
            seq=self._next_seq(),
            path_id=getattr(state, "path_id", 0),
            pc=getattr(issue, "pc", getattr(state, "pc", 0)),
            source_line=source_line,
            source_text=self._get_source_line(getattr(issue, "filename", None), source_line),
            severity=severity,
            detector_name=detector_name,
            issue_kind=issue_kind,
            message=str(getattr(issue, "message", "")),
            confidence=confidence,
            likelihood_score=likelihood,
            constraints_at_issue=constraints_at_issue,
            z3_model=z3_model,
        )
        self._write_event(event, force_flush=True)


__all__ = ["TracerIssueMixin"]
