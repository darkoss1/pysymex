"""Tests for pysymex/analysis/detectors/__init__.py."""

import dis
from pysymex.analysis.detectors import __all__, default_registry


def MockInstr(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    import dis

    def _dummy() -> None:
        pass

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


def test_exports() -> None:
    """Test module exports."""
    assert len(__all__) >= 0
    assert isinstance(__all__, list)


def test_default_registry_excludes_runtime_unreachable_detector() -> None:
    """Default detector registry should not include runtime unreachable-code checks."""
    available = default_registry.list_available()
    assert "unreachable-code" not in available


def test_default_registry_excludes_logical_contradiction_detector() -> None:
    """Logical contradiction detector stays opt-in until precision is improved."""
    available = default_registry.list_available()
    assert "logical-contradiction" not in available
