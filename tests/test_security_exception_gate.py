from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.security_exception_gate import evaluate_audit

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
TARGET_IDS = ("PYSEC-2026-3740", "GHSA-8mgp-746c-j5xp", "CVE-2026-81726")
ROOT = Path(__file__).parents[1]


def _audit(
    *,
    package: str = "nltk",
    version: str = "3.10.3",
    advisory_ids: tuple[str, ...] = TARGET_IDS,
) -> dict[str, object]:
    return {
        "dependencies": [
            {
                "name": package,
                "version": version,
                "vulns": [
                    {
                        "id": advisory_ids[0],
                        "aliases": list(advisory_ids[1:]),
                        "fix_versions": [],
                        "description": "advisory evidence",
                    }
                ],
            }
        ],
        "fixes": [],
    }


def _approval(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "owner": "Maintainer Name",
        "reference": "SEC-2026-042",
        "risk_acceptance": "Accept the unresolved NLTK downstream exposure for this scope.",
        "package": "nltk",
        "version": "3.10.3",
        "advisories": list(TARGET_IDS),
        "scope": "Reviewed Parser AST to LlamaIndex TextNode conversion only.",
        "approved_at": "2026-09-28T11:00:00Z",
        "expires_at": "2026-10-01T11:00:00Z",
    }
    record.update(overrides)
    return record


def _vuln(
    advisory_id: str, aliases: list[str] | None = None
) -> dict[str, object]:
    return {
        "id": advisory_id,
        "aliases": aliases or [],
        "fix_versions": [],
        "description": "additional finding",
    }


def test_valid_clean_audit_is_clean_and_passes() -> None:
    result = evaluate_audit(
        {"dependencies": [{"name": "example", "version": "1.0", "vulns": []}], "fixes": []},
        None,
        now=NOW,
    )

    assert result["audit_status"] == "PASS"
    assert result["disposition"] == "CLEAN"
    assert result["reasons"] == []


def test_target_finding_without_approval_remains_blocked() -> None:
    result = evaluate_audit(_audit(), None, now=NOW)

    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "BLOCKED"
    assert "approval" in " ".join(result["reasons"]).lower()


@pytest.mark.parametrize("advisory_id", TARGET_IDS)
def test_each_canonical_id_or_alias_can_be_approved(advisory_id: str) -> None:
    audit = _audit(advisory_ids=(advisory_id,))

    result = evaluate_audit(audit, _approval(advisories=[advisory_id]), now=NOW)

    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "APPROVED_EXCEPTION"


@pytest.mark.parametrize(
    ("package", "version"),
    [("other-package", "3.10.3"), ("nltk", "3.10.2"), ("nltk", "3.10.4")],
)
def test_wrong_package_or_version_cannot_use_exception(package: str, version: str) -> None:
    result = evaluate_audit(_audit(package=package, version=version), _approval(), now=NOW)

    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "BLOCKED"


@pytest.mark.parametrize(
    "advisory_ids",
    [
        ("UNKNOWN-2026-1",),
        ("PYSEC-2026-3740", "UNKNOWN-2026-1"),
        ("PYSEC-2026-3740", "OTHER-ADVISORY-1"),
    ],
)
def test_unknown_or_mixed_ids_cannot_be_hidden_by_alias(
    advisory_ids: tuple[str, ...],
) -> None:
    result = evaluate_audit(_audit(advisory_ids=advisory_ids), _approval(), now=NOW)

    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "BLOCKED"


def test_unrelated_finding_blocks_target_exception() -> None:
    audit = _audit()
    dependencies = audit["dependencies"]
    assert isinstance(dependencies, list)
    dependencies.append(
        {"name": "another-package", "version": "1.2", "vulns": [_vuln("GHSA-other")]}
    )

    result = evaluate_audit(audit, _approval(), now=NOW)

    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "BLOCKED"


@pytest.mark.parametrize(
    "audit",
    [
        None,
        {},
        {"dependencies": []},
        {"dependencies": [{"name": "nltk", "version": "3.10.3"}], "fixes": []},
        {"dependencies": "invalid", "fixes": []},
        {"dependencies": [None], "fixes": []},
        {"dependencies": [{"name": "nltk", "version": "3.10.3", "vulns": None}], "fixes": []},
        {"dependencies": [], "fixes": [], "skipped": [{"name": "unknown"}]},
        {"dependencies": [], "fixes": [], "skipped": "unknown"},
        {"dependencies": [], "fixes": [{"unexpected": "shape"}]},
    ],
)
def test_empty_incomplete_or_skipped_audit_cannot_pass(audit: object) -> None:
    result = evaluate_audit(audit, None, now=NOW)

    assert result["audit_status"] == "INVALID"
    assert result["disposition"] == "BLOCKED"


def test_malformed_target_vulnerability_cannot_pass() -> None:
    audit = _audit()
    dependencies = audit["dependencies"]
    assert isinstance(dependencies, list)
    dependency = dependencies[0]
    assert isinstance(dependency, dict)
    dependency["vulns"] = [{"id": "PYSEC-2026-3740"}]

    result = evaluate_audit(audit, None, now=NOW)

    assert result["audit_status"] == "INVALID"
    assert result["disposition"] == "BLOCKED"


@pytest.mark.parametrize(
    "approval",
    [
        None,
        [],
        {},
        _approval(owner=""),
        _approval(reference=""),
        _approval(risk_acceptance=""),
        _approval(package="other-package"),
        _approval(version="3.10.2"),
        _approval(advisories=["UNKNOWN-2026-1"]),
        _approval(scope=""),
    ],
)
def test_missing_or_malformed_approval_blocks_target_finding(approval: object) -> None:
    result = evaluate_audit(_audit(), approval, now=NOW)

    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "BLOCKED"


@pytest.mark.parametrize(
    ("approved_at", "expires_at"),
    [
        ("2026-09-28T13:00:00Z", "2026-09-29T13:00:00Z"),
        ("2026-09-28T11:00:00Z", "2026-09-28T11:00:00Z"),
        ("2026-09-28T12:00:00Z", "2026-09-28T11:00:00Z"),
        ("2026-09-21T12:00:00Z", "2026-09-28T12:00:00Z"),
        ("2026-09-28T11:00:00Z", "2026-10-05T12:00:00Z"),
        ("2026-09-28T11:00:00+00:00", "2026-09-29T11:00:00Z"),
        ("2026-09-28X11:00:00Z", "2026-09-29T11:00:00Z"),
        ("2026-09-28 11:00:00Z", "2026-09-29T11:00:00Z"),
        ("2026-09-28T11:00:00+00:00Z", "2026-09-29T11:00:00Z"),
        ("2026-09-28T11:00:00+01:00", "2026-09-29T11:00:00Z"),
        ("not-a-time", "2026-09-29T11:00:00Z"),
    ],
)
def test_invalid_approval_times_block(
    approved_at: str, expires_at: str
) -> None:
    approval = _approval(approved_at=approved_at, expires_at=expires_at)

    result = evaluate_audit(_audit(), approval, now=NOW)

    assert result["disposition"] == "BLOCKED"


@pytest.mark.parametrize("hours", [1, 167, 168])
def test_positive_approval_duration_at_or_below_limit_is_valid(hours: int) -> None:
    approval = _approval(
        approved_at="2026-09-28T09:00:00Z",
        expires_at=(datetime(2026, 9, 28, 9, tzinfo=UTC) + timedelta(hours=hours)).isoformat().replace(
            "+00:00", "Z"
        ),
    )

    result = evaluate_audit(
        _audit(), approval, now=datetime(2026, 9, 28, 9, 30, tzinfo=UTC)
    )

    assert result["disposition"] == "APPROVED_EXCEPTION"


def test_valid_utc_timestamps_allow_six_fractional_digits() -> None:
    approval = _approval(
        approved_at="2026-09-28T11:00:00.123456Z",
        expires_at="2026-10-05T11:00:00.123456Z",
    )

    result = evaluate_audit(_audit(), approval, now=NOW)

    assert result["disposition"] == "APPROVED_EXCEPTION"


def test_now_equal_to_expiry_is_expired() -> None:
    approval = _approval(expires_at="2026-09-28T12:00:00Z")

    result = evaluate_audit(_audit(), approval, now=NOW)

    assert result["disposition"] == "BLOCKED"


def test_injected_evaluation_clock_must_have_zero_utc_offset() -> None:
    non_utc_clock = datetime(
        2026, 9, 28, 14, tzinfo=timezone(timedelta(hours=2))
    )

    result = evaluate_audit(_audit(), _approval(), now=non_utc_clock)

    assert result["audit_status"] == "INVALID"
    assert result["disposition"] == "BLOCKED"


def test_evaluator_does_not_mutate_raw_audit_input() -> None:
    audit = _audit()
    original = deepcopy(audit)

    evaluate_audit(audit, None, now=NOW)

    assert audit == original


@pytest.mark.parametrize(
    ("audit_bytes", "expected_fragment"),
    [(b"", "audit"), (b"{bad", "JSON"), (b"{}", "audit")],
)
def test_cli_invalid_audit_json_fails_closed(
    tmp_path: Path, audit_bytes: bytes, expected_fragment: str
) -> None:
    audit_path = tmp_path / "audit.json"
    audit_path.write_bytes(audit_bytes)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/security_exception_gate.py"), "--audit", str(audit_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "Traceback" not in completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["disposition"] == "BLOCKED"
    assert expected_fragment.lower() in " ".join(payload["reasons"]).lower()


def test_cli_missing_audit_fails_closed_without_traceback(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.json"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/security_exception_gate.py"), "--audit", str(missing_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "Traceback" not in completed.stderr
    assert json.loads(completed.stdout)["disposition"] == "BLOCKED"


def test_cli_reports_clean_audit_as_pass_with_zero_exit(tmp_path: Path) -> None:
    audit_path = tmp_path / "clean-audit.json"
    audit_path.write_text(
        json.dumps({"dependencies": [{"name": "example", "version": "1.0", "vulns": []}], "fixes": []}),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/security_exception_gate.py"), "--audit", str(audit_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["audit_status"] == "PASS"
    assert result["disposition"] == "CLEAN"


def test_cli_hypothetical_exception_never_relabels_audit_clean(
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "audit.json"
    approval_path = tmp_path / "synthetic-approval.json"
    audit_path.write_text(json.dumps(_audit()), encoding="utf-8")
    cli_now = datetime.now(UTC)
    approval = _approval(
        approved_at=(cli_now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        expires_at=(cli_now + timedelta(hours=71)).isoformat().replace("+00:00", "Z"),
    )
    approval_path.write_text(json.dumps(approval), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/security_exception_gate.py"),
            "--audit",
            str(audit_path),
            "--approval",
            str(approval_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    result = json.loads(completed.stdout)
    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "APPROVED_EXCEPTION"


def test_cli_unreadable_audit_path_fails_closed_without_traceback(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/security_exception_gate.py"),
            "--audit",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "Traceback" not in completed.stderr
    result = json.loads(completed.stdout)
    assert result["audit_status"] == "INVALID"
    assert result["disposition"] == "BLOCKED"


@pytest.mark.parametrize(
    "raw_audit",
    [
        '{"dependencies":[],"dependencies":[],"fixes":[]}',
        '{"dependencies":[{"name":"nltk","version":"3.10.3","vulns":[{"id":"UNKNOWN-1","aliases":[],"fix_versions":[],"description":"finding"}],"vulns":[]}],"fixes":[]}',
        '{"dependencies":[{"name":"nltk","version":"3.10.3","vulns":[{"id":"UNKNOWN-1","id":"PYSEC-2026-3740","aliases":[],"fix_versions":[],"description":"finding"}]}],"fixes":[]}',
        '{"dependencies":[{"name":"nltk","version":"3.10.3","vulns":[{"id":"PYSEC-2026-3740","aliases":["UNKNOWN-1"],"aliases":[],"fix_versions":[],"description":"finding"}]}],"fixes":[]}',
    ],
)
def test_cli_rejects_duplicate_audit_json_members(
    tmp_path: Path, raw_audit: str
) -> None:
    audit_path = tmp_path / "duplicate-audit.json"
    audit_path.write_text(raw_audit, encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/security_exception_gate.py"), "--audit", str(audit_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "Traceback" not in completed.stderr
    result = json.loads(completed.stdout)
    assert result["audit_status"] == "INVALID"
    assert result["disposition"] == "BLOCKED"
    assert "duplicate" in " ".join(result["reasons"]).lower()


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_cli_rejects_nonstandard_audit_json_constants(
    tmp_path: Path, constant: str
) -> None:
    audit_path = tmp_path / "nonstandard-audit.json"
    audit_path.write_text(
        f'{{"dependencies":[{{"name":"nltk","version":"3.10.3","vulns":[{{"id":"PYSEC-2026-3740","aliases":[],"fix_versions":[],"description":{constant}}}]}}],"fixes":[]}}',
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/security_exception_gate.py"), "--audit", str(audit_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    result = json.loads(completed.stdout)
    assert result["audit_status"] == "INVALID"
    assert "JSON" in " ".join(result["reasons"])


def test_cli_rejects_duplicate_approval_fields(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.json"
    approval_path = tmp_path / "duplicate-approval.json"
    audit_path.write_text(json.dumps(_audit()), encoding="utf-8")
    cli_now = datetime.now(UTC)
    approval = _approval(
        approved_at=(cli_now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        expires_at=(cli_now + timedelta(hours=71)).isoformat().replace("+00:00", "Z"),
    )
    raw_approval = json.dumps(approval).replace(
        '"owner": "Maintainer Name"',
        '"owner": "", "owner": "Maintainer Name"',
    )
    approval_path.write_text(raw_approval, encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/security_exception_gate.py"),
            "--audit",
            str(audit_path),
            "--approval",
            str(approval_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "Traceback" not in completed.stderr
    result = json.loads(completed.stdout)
    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "BLOCKED"
    assert "duplicate" in " ".join(result["reasons"]).lower()


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_cli_rejects_nonstandard_approval_constants(
    tmp_path: Path, constant: str
) -> None:
    audit_path = tmp_path / "audit.json"
    approval_path = tmp_path / "nonstandard-approval.json"
    audit_path.write_text(json.dumps(_audit()), encoding="utf-8")
    approval_path.write_text(f'{{"owner":{constant}}}', encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/security_exception_gate.py"),
            "--audit",
            str(audit_path),
            "--approval",
            str(approval_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    result = json.loads(completed.stdout)
    assert result["audit_status"] == "FAIL"
    assert result["disposition"] == "BLOCKED"
    assert "approval JSON" in " ".join(result["reasons"])


@pytest.mark.parametrize("kind", ["audit", "approval"])
def test_cli_invalid_utf8_fails_closed_structurally(
    tmp_path: Path, kind: str
) -> None:
    audit_path = tmp_path / "audit.json"
    approval_path = tmp_path / "approval.json"
    audit_path.write_text(json.dumps(_audit()), encoding="utf-8")
    approval_path.write_bytes(b"\xff")
    if kind == "audit":
        audit_path.write_bytes(b"\xff")

    command = [
        sys.executable,
        str(ROOT / "scripts/security_exception_gate.py"),
        "--audit",
        str(audit_path),
    ]
    if kind == "approval":
        command.extend(["--approval", str(approval_path)])
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "Traceback" not in completed.stderr
    result = json.loads(completed.stdout)
    assert result["disposition"] == "BLOCKED"
    if kind == "audit":
        assert result["audit_status"] == "INVALID"
        assert "UTF-8" in " ".join(result["reasons"])
    else:
        assert result["audit_status"] == "FAIL"
        assert "approval" in " ".join(result["reasons"]).lower()
        assert "UTF-8" in " ".join(result["reasons"])
