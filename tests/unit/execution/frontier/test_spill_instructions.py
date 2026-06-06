from __future__ import annotations

import dis
from typing import cast

import pytest

from pysymex.execution.frontier.spill.instructions import (
    SpillInstructionDecodeError,
    current_instructions_payload,
    decode_current_instructions,
)


def _instructions() -> tuple[dis.Instruction, ...]:
    return tuple(dis.get_instructions(compile("x = 1\n", "<spill-instructions>", "exec")))


def _instruction_payload() -> dict[str, object]:
    payloads = current_instructions_payload(_instructions())
    assert payloads is not None
    payload = payloads[0]
    assert isinstance(payload, dict)
    return cast("dict[str, object]", payload)


def test_current_instructions_payload_round_trips_dis_instructions() -> None:
    """Exact CPython instruction metadata round-trips through JSON-safe payloads."""
    instructions = _instructions()
    payload = current_instructions_payload(instructions)

    assert payload is not None
    assert decode_current_instructions(payload) == list(instructions)


def test_current_instructions_payload_round_trips_optional_and_json_fields() -> None:
    """Instruction spill accepts JSON-safe optional CPython metadata."""
    instruction = _instructions()[0]._replace(
        argval={"items": [1, None]},
        starts_line=7,
        positions=None,
    )
    payload = current_instructions_payload((instruction,))

    assert payload is not None
    assert decode_current_instructions(payload) == [instruction]


def test_current_instructions_payload_accepts_empty_instruction_lists() -> None:
    """Empty current-instruction lists are supported and distinct from missing lists."""
    assert current_instructions_payload(()) == []
    assert decode_current_instructions([]) == []
    assert decode_current_instructions(None) is None


def test_current_instructions_payload_rejects_unsupported_instruction_shapes() -> None:
    """Instruction spill rejects non-instructions and object-heavy instruction fields."""
    instruction = _instructions()[0]
    assert current_instructions_payload((object(),)) is None
    assert current_instructions_payload((instruction._replace(argval=object()),)) is None
    if "label" in instruction._fields:
        assert current_instructions_payload((instruction._replace(label=object()),)) is None
    assert current_instructions_payload((instruction._replace(positions=object()),)) is None
    if "cache_info" in instruction._fields:
        assert current_instructions_payload((instruction._replace(cache_info=object()),)) is None
    assert (
        current_instructions_payload(
            (
                instruction._replace(
                    positions=dis.Positions(
                        lineno=cast("int | None", True),
                        end_lineno=None,
                        col_offset=None,
                        end_col_offset=None,
                    )
                ),
            )
        )
        is None
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("opname", None),
        ("opcode", True),
        ("arg", True),
        ("argval", object()),
        ("argrepr", None),
        ("offset", False),
        ("start_offset", None),
        ("starts_line", "bad"),
        ("line_number", True),
        ("label", object()),
        ("positions", "bad"),
        ("positions", {"lineno": True}),
        ("cache_info", {}),
    ],
)
def test_decode_current_instructions_rejects_malformed_instruction_fields(
    field: str,
    value: object,
) -> None:
    """Malformed instruction fields never reconstruct partial instruction lists."""
    payload = _instruction_payload()
    payload[field] = value

    with pytest.raises(SpillInstructionDecodeError):
        decode_current_instructions([payload])


@pytest.mark.parametrize(
    "raw_instructions",
    [
        {"bad": "container"},
        ["not-object"],
        [{1: "bad"}],
    ],
)
def test_decode_current_instructions_rejects_malformed_containers(
    raw_instructions: object,
) -> None:
    """Malformed instruction containers fail closed."""
    with pytest.raises(SpillInstructionDecodeError):
        decode_current_instructions(raw_instructions)
