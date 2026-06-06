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

from __future__ import annotations

import json

from pysymex.sandbox.bridge.types import normalize_mapping

WORKER_ENVELOPE_KEYS = frozenset(
    {
        "ok",
        "payload",
        "return_value",
        "error",
        "traceback",
        "exception_type",
        "exception_message",
    }
)


class PayloadParseStatus:
    """String status values returned by marker-delimited payload extraction."""

    OK = "ok"
    MISSING = "missing"
    MALFORMED = "malformed"
    MULTIPLE = "multiple"


def extract_payload(stdout_text: str, marker: str) -> tuple[str, dict[str, object] | None, str]:
    """Extract one marker-prefixed JSON object from worker standard output.

    Args:
        stdout_text: Decoded standard output captured from a sandbox worker.
        marker: Line prefix identifying the worker result payload.

    Returns:
        A tuple of output with marker lines removed, the normalized JSON object
        when exactly one valid marked mapping is present, and a
        `PayloadParseStatus` value describing extraction.

    Notes:
        A second marker invalidates a previously parsed payload and reports
        `MULTIPLE`. Marker-free lines are preserved as cleaned worker output.
    """
    output_lines: list[str] = []
    parsed: dict[str, object] | None = None
    status = PayloadParseStatus.MISSING
    marker_count = 0
    for line in stdout_text.splitlines():
        if line.startswith(marker):
            marker_count += 1
            if marker_count > 1:
                status = PayloadParseStatus.MULTIPLE
                parsed = None
                continue
            raw_payload = line[len(marker) :]
            try:
                loaded = json.loads(raw_payload)
                parsed = normalize_mapping(loaded)
            except json.JSONDecodeError:
                parsed = None
            if parsed is None:
                status = PayloadParseStatus.MALFORMED
            else:
                status = PayloadParseStatus.OK
            continue
        output_lines.append(line)
    cleaned = "\n".join(output_lines)
    if stdout_text.endswith("\n") and cleaned:
        cleaned += "\n"
    return cleaned, parsed, status


def validate_worker_envelope(parsed: dict[str, object]) -> None:
    """Validate the permitted fields and success flag in a worker envelope.

    Args:
        parsed: Normalized marker payload returned by `extract_payload`.

    Raises:
        SandboxProtocolError: If the envelope contains an unsupported field or
            its `ok` field is not a boolean.
    """
    from pysymex.sandbox.errors import SandboxProtocolError

    unexpected = sorted(set(parsed) - set(WORKER_ENVELOPE_KEYS))
    if unexpected:
        raise SandboxProtocolError(
            "Sandbox worker produced unexpected envelope field(s): " + ", ".join(unexpected)
        )
    ok = parsed.get("ok")
    if not isinstance(ok, bool):
        raise SandboxProtocolError("Sandbox worker envelope field 'ok' must be boolean")
