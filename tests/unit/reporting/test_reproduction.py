from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.reporting.reproduction import ReproductionGenerator


def _issue(
    counterexample: dict[str, object] | None,
    *,
    function_name: str | None = None,
    filename: str | None = None,
    class_name: str | None = None,
    message: str = "boom",
) -> Issue:
    return Issue(
        kind=IssueKind.TYPE_ERROR,
        message=message,
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


def test_reproduction_script_executes_from_source_file_path(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text("def target(x: int) -> int:\n    return 1 // x\n", encoding="utf-8")

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 0}), "target", str(source))

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_uses_safe_python_literals_for_strings(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "def target(text: str) -> str:\n"
        '    if "\'" in text:\n'
        "        raise ValueError(text)\n"
        "    return text\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(
        _issue({"text": "it's\nbroken"}, message='message with """ and \n newline'),
        "target",
        str(source),
    )

    assert out is not None
    out_path = Path(out)
    compile(out_path.read_text(encoding="utf-8"), out, "exec")
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ValueError" in completed.stdout


def test_reproduction_supports_keyword_only_defaults(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "def target(x: int, *, scale: int = 1) -> int:\n    return scale // x\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 0}), "target", str(source))

    assert out is not None
    content = Path(out).read_text(encoding="utf-8")
    assert "scale=1" not in content
    compile(content, out, "exec")


def test_reproduction_supports_positional_only_args(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "def target(x: int, /, y: int) -> int:\n    return y // x\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 0, "y": 1}), "target", str(source))

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_supports_simple_class_methods(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "class Target:\n"
        "    def __init__(self, base: int = 1) -> None:\n"
        "        self.base = base\n"
        "    def target(self, x: int) -> int:\n"
        "        return self.base // x\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 0}), "target", str(source), class_name="Target")

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_preserves_package_import_context(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "helpers.py").write_text("ZERO = 0\n", encoding="utf-8")
    source = package_dir / "sample_mod.py"
    source.write_text(
        "from .helpers import ZERO\n\ndef target(x: int) -> int:\n    return x // ZERO\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 1}), "target", str(source))

    assert out is not None
    content = Path(out).read_text(encoding="utf-8")
    assert "MODULE_NAME = 'pkg.sample_mod'" in content
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_awaits_async_functions(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "async def target(x: int) -> int:\n    return 1 // x\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 0}), "target", str(source))

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_omits_default_expression_arguments(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "ZERO = 0\n\ndef target(x: int, scale: int = ZERO) -> int:\n    return x // scale\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 1}), "target", str(source))

    assert out is not None
    content = Path(out).read_text(encoding="utf-8")
    assert "scale=ZERO" not in content
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_expands_varargs_from_counterexample(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "def target(*values: int) -> int:\n    return values[0] // values[1]\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"values": (1, 0)}), "target", str(source))

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_expands_kwargs_from_counterexample(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "def target(**values: int) -> int:\n    return values['x'] // values['y']\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"values": {"x": 1, "y": 0}}), "target", str(source))

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_orders_mixed_varargs_and_kwargs(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "def target(prefix: int, *values: int, **opts: int) -> int:\n"
        "    return (prefix + values[0] + opts['bonus']) // values[1]\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(
        _issue({"prefix": 1, "values": (2, 0), "opts": {"bonus": 3}}),
        "target",
        str(source),
    )

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_builds_positional_only_init_args(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "class Target:\n"
        "    def __init__(self, base: int, /) -> None:\n"
        "        self.base = base\n"
        "    def target(self, x: int) -> int:\n"
        "        return self.base // x\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 0}), "target", str(source), class_name="Target")

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout


def test_reproduction_calls_decorated_positional_wrappers(tmp_path: Path) -> None:
    source = tmp_path / "sample_mod.py"
    source.write_text(
        "def dec(func):\n"
        "    def wrapper(*args):\n"
        "        return func(*args)\n"
        "    return wrapper\n\n"
        "@dec\n"
        "def target(x: int) -> int:\n"
        "    return 1 // x\n",
        encoding="utf-8",
    )

    gen = ReproductionGenerator(output_dir=str(tmp_path / "repros"))
    out = gen.generate(_issue({"x": 0}), "target", str(source))

    assert out is not None
    completed = subprocess.run(
        [sys.executable, out],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "CRASH REPRODUCED: ZeroDivisionError" in completed.stdout
