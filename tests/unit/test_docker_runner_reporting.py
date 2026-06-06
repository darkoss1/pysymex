import pytest

from tests.docker.models import TestResult as DockerTestResult
from tests.docker.models import TestStatus as DockerTestStatus
from tests.docker.reporting import DockerReportingMixin


class _ReportingRunner(DockerReportingMixin):
    pass


def _result(status: DockerTestStatus) -> DockerTestResult:
    return DockerTestResult(
        version="3.13",
        container_name="pysymex-py313",
        status=status,
        exit_code=0 if status == DockerTestStatus.SUCCESS else 1,
        duration=1.25,
        passed=1 if status == DockerTestStatus.SUCCESS else 0,
        failed=0 if status == DockerTestStatus.SUCCESS else 1,
        errors=0,
        skipped=0,
        xfailed=0,
        xpassed=0,
        total=1,
        output="",
        error_output="failure" if status != DockerTestStatus.SUCCESS else "",
    )


def test_docker_report_symbols_are_readable_ascii(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = _ReportingRunner().print_results({"3.13": _result(DockerTestStatus.SUCCESS)})

    output = capsys.readouterr().out

    assert exit_code == 0
    assert "OK Python 3.13" in output
    assert "OK All tests passed across all Python versions!" in output
    assert chr(0x00C3) not in output
