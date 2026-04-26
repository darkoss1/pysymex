from pysymex.accel.backends import BackendType, BackendInfo, BackendError


class TestBackendType:
    def test_enum_values(self) -> None:
        assert BackendType.SAT == "sat"
        assert BackendType.CPU == "cpu"
        assert BackendType.REFERENCE == "reference"


class TestBackendInfo:
    def test_initialization_defaults(self) -> None:
        info = BackendInfo(
            backend_type=BackendType.CPU,
            name="Test",
            available=True,
            max_treewidth=10,
        )
        assert info.supports_async is False
        assert info.device_memory_mb == 0
        assert info.compute_units == 1
        assert info.throughput_estimate is None
        assert info.error_message is None


class TestBackendError:
    def test_initialization(self) -> None:
        err = BackendError("test error")
        assert str(err) == "test error"
