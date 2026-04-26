import z3
import numpy as np
from unittest.mock import patch

from pysymex.accel.backends import BackendType
from pysymex.accel.backends import sat
from pysymex.accel.bytecode import compile_constraint


def test_is_available_returns_bool() -> None:
    assert isinstance(sat.is_available(), bool)


def test_get_info_returns_available_when_pysat_installed() -> None:
    with patch("pysymex.accel.backends.sat.is_available", return_value=True):
        info = sat.get_info()
    assert info.backend_type is BackendType.SAT
    assert info.available is True
    assert info.max_treewidth == 100000
    assert info.supports_async is True
    assert info.compute_units == 1


def test_get_info_returns_unavailable_when_pysat_missing() -> None:
    with patch("pysymex.accel.backends.sat.is_available", return_value=False):
        info = sat.get_info()
    assert info.backend_type is BackendType.SAT
    assert info.available is False
    assert info.max_treewidth == 0
    assert info.error_message == "python-sat not installed"


def test_evaluate_bag_returns_bitmap() -> None:
    x = z3.Bool("x")
    constraint = compile_constraint(x, ["x"])
    res = sat.evaluate_bag(constraint)
    assert res.dtype == np.uint8
    assert res.shape == (1,)


from _pytest.logging import LogCaptureFixture


def test_evaluate_bag_logs_warning_when_unavailable(caplog: LogCaptureFixture) -> None:
    import logging

    caplog.set_level(logging.DEBUG)
    x = z3.Bool("x")
    constraint = compile_constraint(x, ["x"])
    with patch("pysymex.accel.backends.sat.is_available", return_value=False):
        sat.evaluate_bag(constraint)
    assert "PySAT not available; falling back to reference backend" in caplog.text


def test_warmup_returns_none() -> None:
    assert sat.warmup() is None
