from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

PROBE = Path(__file__).with_name("security_sentinel_probe.py")
_PROBE_TIMEOUT_SECONDS = 30.0


def _probe(mode: str) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(PROBE), mode]
    with TemporaryDirectory(prefix="security-sentinel-probe-") as working_directory:
        try:
            return subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                cwd=working_directory,
                timeout=_PROBE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(
                command,
                124,
                "",
                f"PROBE_TIMEOUT after {_PROBE_TIMEOUT_SECONDS:g} seconds",
            )


@pytest.mark.parametrize(
    "mode", ["import-companion", "import-schema", "import-shim"]
)
def test_fresh_imports_do_not_write_connect_or_spawn(mode: str) -> None:
    completed = _probe(mode)

    assert completed.returncode == 0, completed.stderr
    assert f"PROBE_PASS:{mode}" in completed.stdout


@pytest.mark.parametrize(
    "mode",
    [
        "convert-empty-companion",
        "convert-nodes-companion",
        "convert-empty-shim",
        "convert-nodes-shim",
    ],
)
def test_conversion_preserves_node_data_without_observed_io(mode: str) -> None:
    completed = _probe(mode)

    assert completed.returncode == 0, completed.stderr
    assert f"PROBE_PASS:{mode}" in completed.stdout


@pytest.mark.parametrize(
    ("mode", "marker"),
    [
        ("negative-write", "SENTINEL_WRITE"),
        ("negative-read", "SENTINEL_READ"),
        ("negative-network", "SENTINEL_NETWORK"),
        ("negative-process", "SENTINEL_PROCESS"),
        ("negative-model-api", "SENTINEL_WRITE"),
        ("negative-model-read-api", "SENTINEL_READ"),
        ("negative-model-load", "SENTINEL_MODEL_LOAD"),
    ],
)
def test_intentional_negative_controls_trip_expected_sentinel(
    mode: str, marker: str
) -> None:
    completed = _probe(mode)

    assert completed.returncode == 73
    assert marker in completed.stderr
    assert "SENTINEL_NOT_TRIGGERED" not in completed.stderr


def test_caught_sentinel_violation_still_fails_probe() -> None:
    completed = _probe("negative-caught-write")

    assert completed.returncode == 73
    assert "SENTINEL_WRITE" in completed.stderr
    assert "PROBE_PASS" not in completed.stdout


def test_probe_timeout_is_finite_and_reports_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timed_out_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        timeout = kwargs.get("timeout")
        assert isinstance(timeout, (int, float)) and timeout > 0
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr(subprocess, "run", timed_out_run)

    completed = _probe("import-schema")

    assert completed.returncode == 124
    assert "PROBE_TIMEOUT" in completed.stderr
