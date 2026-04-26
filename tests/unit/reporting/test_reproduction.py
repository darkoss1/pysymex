from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from pysymex.reporting.reproduction import ReproductionGenerator


class _Kind:
    name = "TYPE_ERROR"


class _Issue:
    def __init__(self, counterexample: dict[str, object] | None) -> None:
        self.counterexample = counterexample
        self.kind = _Kind()
        self.message = "boom"


def test_reproduction_generator_returns_none_without_counterexample(tmp_path: Path) -> None:
    gen = ReproductionGenerator(output_dir=str(tmp_path))
    path = gen.generate(cast("Any", _Issue(None)), "target", "src.py")
    assert path is None


def test_reproduction_generator_writes_script_for_function(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text("def target(x: int) -> int:\n    return 1 // x\n", encoding="utf-8")

    gen = ReproductionGenerator(output_dir=str(tmp_path))
    out = gen.generate(cast("Any", _Issue({"x": 0})), "target", str(source))

    assert out is not None
    out_path = Path(out)
    assert out_path.exists()
    assert "target" in out_path.read_text(encoding="utf-8")
