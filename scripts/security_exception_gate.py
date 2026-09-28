#!/usr/bin/env python3
"""Fail-closed local evaluator for the proposed NLTK audit exception."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

TARGET_PACKAGE = "nltk"
TARGET_VERSION = "3.10.3"
TARGET_IDS = frozenset(
    {"PYSEC-2026-3740", "GHSA-8mgp-746c-j5xp", "CVE-2026-81726"}
)
TARGET_SCOPE = "Reviewed Parser AST to LlamaIndex TextNode conversion only."
MAX_APPROVAL_AGE_HOURS = 168
_AUDIT_FIELDS = {"dependencies", "fixes"}
_DEPENDENCY_FIELDS = {"name", "version", "vulns"}
_VULNERABILITY_FIELDS = {"id", "aliases", "fix_versions", "description"}
_FIX_FIELDS = {"name", "old_version", "new_version"}
_SKIPPED_FIX_FIELDS = {"name", "skip_reason"}
_APPROVAL_FIELDS = {
    "owner",
    "reference",
    "risk_acceptance",
    "package",
    "version",
    "advisories",
    "scope",
    "approved_at",
    "expires_at",
}
_UTC_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z"
)


class _InvalidJSON(ValueError):
    """Raised for duplicate members or non-standard JSON constants."""


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidJSON(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise _InvalidJSON(f"non-standard JSON constant is not allowed: {value}")


def _result(
    audit_status: str, disposition: str, reasons: list[str]
) -> dict[str, object]:
    return {
        "audit_status": audit_status,
        "disposition": disposition,
        "reasons": reasons,
    }


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_audit(audit: object) -> tuple[list[tuple[str, str, dict[str, Any]]], str | None]:
    if (
        not isinstance(audit, dict)
        or not set(audit) >= _AUDIT_FIELDS
        or not set(audit) <= _AUDIT_FIELDS | {"skipped"}
    ):
        return [], "audit must contain exactly dependencies and fixes"
    dependencies = audit.get("dependencies")
    fixes = audit.get("fixes")
    if not isinstance(dependencies, list) or not dependencies:
        return [], "audit dependencies must be a non-empty list"
    if not isinstance(fixes, list):
        return [], "audit fixes must be a list"
    for fix in fixes:
        if not isinstance(fix, dict) or frozenset(fix) not in {
            frozenset(_FIX_FIELDS),
            frozenset(_SKIPPED_FIX_FIELDS),
        }:
            return [], "audit fix entry is incomplete or malformed"
        if any(not _nonempty_string(value) for value in fix.values()):
            return [], "audit fix entry is incomplete or malformed"
    skipped = audit.get("skipped", [])
    if not isinstance(skipped, list) or skipped:
        return [], "audit includes skipped or invalid dependency results"

    findings: list[tuple[str, str, dict[str, Any]]] = []
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != _DEPENDENCY_FIELDS:
            return [], "audit dependency entry is incomplete or malformed"
        name = dependency.get("name")
        version = dependency.get("version")
        vulns = dependency.get("vulns")
        if not _nonempty_string(name) or not _nonempty_string(version):
            return [], "audit dependency identity is incomplete or malformed"
        if not isinstance(vulns, list):
            return [], "audit dependency vulnerabilities must be a list"
        for vuln in vulns:
            if not isinstance(vuln, dict) or set(vuln) != _VULNERABILITY_FIELDS:
                return [], "audit vulnerability entry is incomplete or malformed"
            advisory_id = vuln.get("id")
            aliases = vuln.get("aliases")
            fix_versions = vuln.get("fix_versions")
            description = vuln.get("description")
            if (
                not _nonempty_string(advisory_id)
                or not isinstance(aliases, list)
                or any(not _nonempty_string(alias) for alias in aliases)
                or not isinstance(fix_versions, list)
                or any(not _nonempty_string(version) for version in fix_versions)
                or not isinstance(description, str)
            ):
                return [], "audit vulnerability entry is incomplete or malformed"
            findings.append((name.lower(), version, vuln))
    return findings, None


def _parse_utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        return None
    return parsed


def _approval_error(
    approval: object,
    target_vulns: list[dict[str, Any]],
    *,
    now: datetime,
) -> str | None:
    if isinstance(approval, dict) and set(approval) == {"_input_error"}:
        input_error = approval.get("_input_error")
        return input_error if isinstance(input_error, str) else "approval input is invalid"
    if not isinstance(approval, dict) or set(approval) != _APPROVAL_FIELDS:
        return "approval record is missing or has an invalid schema"
    for field in ("owner", "reference", "risk_acceptance"):
        if not _nonempty_string(approval.get(field)):
            return f"approval {field} is required"
    if (
        approval.get("package") != TARGET_PACKAGE
        or approval.get("version") != TARGET_VERSION
        or approval.get("scope") != TARGET_SCOPE
    ):
        return "approval package, version, or scope does not match the target"
    advisory_ids = approval.get("advisories")
    if (
        not isinstance(advisory_ids, list)
        or not advisory_ids
        or any(not _nonempty_string(advisory_id) for advisory_id in advisory_ids)
    ):
        return "approval advisory identity is missing or invalid"
    approval_ids = set(advisory_ids)
    if not approval_ids <= TARGET_IDS:
        return "approval contains an unknown advisory identity"
    for vuln in target_vulns:
        observed_ids = {vuln["id"], *vuln["aliases"]}
        if not observed_ids <= TARGET_IDS or not (observed_ids & approval_ids):
            return "target finding contains unknown or unapproved advisory identities"

    approved_at = _parse_utc_timestamp(approval.get("approved_at"))
    expires_at = _parse_utc_timestamp(approval.get("expires_at"))
    if approved_at is None or expires_at is None:
        return "approval timestamps must be exact UTC ISO-8601 values ending in Z"
    if approved_at > now:
        return "approval timestamp is in the future"
    duration = expires_at - approved_at
    if duration.total_seconds() <= 0:
        return "approval duration must be positive"
    if duration.total_seconds() > MAX_APPROVAL_AGE_HOURS * 60 * 60:
        return "approval duration exceeds 168 hours"
    if now >= expires_at:
        return "approval has expired"
    return None


def evaluate_audit(
    audit: object, approval: object | None, *, now: datetime
) -> dict[str, object]:
    """Return raw audit status separately from the hypothetical disposition."""
    if (
        now.tzinfo is None
        or now.utcoffset() is None
        or now.utcoffset() != timedelta(0)
    ):
        return _result("INVALID", "BLOCKED", ["evaluation time must have a zero UTC offset"])
    findings, validation_error = _validate_audit(audit)
    if validation_error:
        return _result("INVALID", "BLOCKED", [validation_error])
    if not findings:
        return _result("PASS", "CLEAN", [])

    target_vulns: list[dict[str, Any]] = []
    for name, version, vuln in findings:
        if name == TARGET_PACKAGE and version == TARGET_VERSION:
            target_vulns.append(vuln)
        else:
            return _result(
                "FAIL", "BLOCKED", ["audit contains a finding outside the approved target"]
            )
    approval_error = _approval_error(approval, target_vulns, now=now)
    if approval_error:
        return _result("FAIL", "BLOCKED", [approval_error])
    return _result(
        "FAIL",
        "APPROVED_EXCEPTION",
        ["raw audit remains FAIL; the separately validated exception is hypothetical"],
    )


def _read_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(
            handle,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )


def _cli_result(audit_path: Path, approval_path: Path | None) -> dict[str, object]:
    try:
        audit = _read_json(audit_path)
    except UnicodeDecodeError as exc:
        return _result("INVALID", "BLOCKED", [f"audit JSON UTF-8 decoding error: {exc}"])
    except (json.JSONDecodeError, _InvalidJSON) as exc:
        return _result("INVALID", "BLOCKED", [f"audit JSON is invalid: {exc}"])
    except OSError as exc:
        return _result("INVALID", "BLOCKED", [f"audit input error: {exc}"])

    approval: object | None = None
    if approval_path is not None:
        try:
            approval = _read_json(approval_path)
        except UnicodeDecodeError as exc:
            approval = {"_input_error": f"approval JSON UTF-8 decoding error: {exc}"}
        except (OSError, json.JSONDecodeError, _InvalidJSON) as exc:
            approval = {"_input_error": f"approval JSON input error: {exc}"}
    return evaluate_audit(audit, approval, now=datetime.now(UTC))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--approval", type=Path)
    args = parser.parse_args(argv)
    result = _cli_result(args.audit, args.approval)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["disposition"] in {"CLEAN", "APPROVED_EXCEPTION"} else 2


if __name__ == "__main__":
    sys.exit(main())
