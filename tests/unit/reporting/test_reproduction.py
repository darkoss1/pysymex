from __future__ import annotations

from pathlib import Path

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.reporting.reproduction import ReproductionGenerator


def _issue(
    counterexample: dict[str, object] | None,
    *,
    function_name: str | None = None,
    filename: str | None = None,
    class_name: str | None = None,
) -> Issue:
    return Issue(
        kind=IssueKind.TYPE_ERROR,
        message="boom",
        counterexample=counterexample,
        function_name=function_name,
        filename=filename,
        class_name=class_name,
    )


def test_reproduction_generator_returns_none_without_counterexample(tmp_path: Path) -> None:
    gen = ReproductionGenerator(output_dir=str(tmp_path))
    path = gen.generate(_issue(None), "target", "src.py")
    assert path is None


def test_reproduction_generator_writes_script_for_function(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text("def target(x: int) -> int:\n    return 1 // x\n", encoding="utf-8")

    gen = ReproductionGenerator(output_dir=str(tmp_path))
    out = gen.generate(_issue({"x": 0}), "target", str(source))

    assert out is not None
    out_path = Path(out)
    assert out_path.exists()
    assert "target" in out_path.read_text(encoding="utf-8")


def test_reproduction_generator_generate_script(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text("def target(x: int) -> int:\n    return 1 // x\n", encoding="utf-8")

    gen = ReproductionGenerator(output_dir=str(tmp_path))
    out = gen.generate_script(
        _issue(
            {"x": 0},
            function_name="target",
            filename=str(source),
        )
    )

    assert out is not None
    out_path = Path(out)
    assert out_path.exists()
    assert "repro_type_target.py" in out
