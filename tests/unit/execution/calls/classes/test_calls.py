"""Tests for modeled class-call dispatch ownership."""

from __future__ import annotations

from pysymex._internal.execution.calls.classes.targets import (
    class_target_code,
    class_target_name,
    is_class_like_target,
)


def test_class_call_target_helpers_identify_python_classes() -> None:
    class Sample:
        def __init__(self, value: int) -> None:
            self.value = value

    assert class_target_name(Sample) == "Sample"
    assert is_class_like_target(Sample) is True
    assert class_target_code(Sample) is Sample.__init__.__code__
    assert is_class_like_target(object()) is False
