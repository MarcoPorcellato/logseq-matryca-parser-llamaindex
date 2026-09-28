# Experimental local security controls

**Status: unpublished, inactive, and not an approval or release gate.** These
local controls qualify a narrow adapter path and evaluate a separately supplied
exception record. They do not authorize an exception, merge, release, or
publication. The companion release remains blocked.

## Local audit evaluator

From the repository root, run:

```bash
python scripts/security_exception_gate.py --audit /path/to/pip-audit.json
python scripts/security_exception_gate.py --audit /path/to/pip-audit.json --approval /path/to/approval.json
```

The CLI prints one JSON object with `audit_status`, `disposition`, and
`reasons`. Exit status is zero only for a complete clean audit or a
hypothetical, schema-valid exception; it is nonzero for invalid evidence,
target findings without a valid record, and all other findings. A validated
exception is shown as `audit_status: FAIL` and
`disposition: APPROVED_EXCEPTION`; the raw audit result is never changed or
called clean.

The evaluator accepts the complete `pip-audit --format json` result with a
non-empty dependency list, a `fixes` list, and no skipped dependencies. Target
matching is limited to package `nltk`, version `3.10.3`, and the advisory
identity set `PYSEC-2026-3740`, `GHSA-8mgp-746c-j5xp`, and `CVE-2026-81726`.
Unknown identifiers, mixed identities, wrong package/version, malformed audit
entries, skipped dependencies, or any additional finding block the exception.

A hypothetical approval record must provide `owner`, `reference`,
`risk_acceptance`, `package`, `version`, `advisories`, `scope`, `approved_at`,
and `expires_at`. Its package/version and scope must match the target. Both
timestamps must use the exact extended grammar `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`:
literal `T` and `Z`, with either no fractional part or one to six fractional
digits. Approval cannot be in the future, expiry must be later than approval
and no more than 168 hours after it, and `now == expires_at` is expired. The
CLI uses the local system clock; tests inject time through `evaluate_audit`
only, and that injected clock must have a zero UTC offset.

Audit and approval JSON decoding rejects duplicate member names at every depth
and non-standard numeric tokens (`NaN`, `Infinity`, and `-Infinity`). Invalid
UTF-8, malformed JSON, and duplicate-key input produce structured nonzero
`BLOCKED` results rather than tracebacks.

No real approval record exists. Synthetic records are confined to unit tests
and are not maintainer authorization. Schema validation does not authenticate
the author or verify the advisory against current authoritative sources. Any
future decision needs independently verified maintainer identity, an
authoritative approval reference, fresh advisory review, and explicit risk
acceptance. No renewal is implemented.

The preserved production audit for the qualification dependency export remains
**FAIL**: NLTK `3.10.3`, `PYSEC-2026-3740`, with
`GHSA-8mgp-746c-j5xp` and `CVE-2026-81726` aliases. The advisory discrepancy is
unresolved: the PyPA record's prose includes `3.10.3` as affected while its
machine-readable events mark that version fixed; the GitHub advisory reports
NLTK through `3.10.3` affected with no patched version identified. Recheck both
authoritative records before any future approval or release decision:
[PyPA advisory record](https://github.com/pypa/advisory-database/blob/main/vulns/nltk/PYSEC-2026-3740.yaml),
[GitHub advisory](https://github.com/advisories/GHSA-8mgp-746c-j5xp).

## Adapter-side-effect probes

`tests/test_adapter_side_effects.py` starts a fresh Python process for each
probe. Import probes arm Python-level outbound-socket, write, and process
sentinels before importing the companion, `llama_index.core.schema`, or the
Parser shim. They permit normal read-only module loading. Conversion probes
import dependencies first, then arm read/write, outbound-socket, process, NLTK
model-load, and affected model-API sentinels around empty and non-empty
conversion. Non-empty fixtures include instruction-like text, metadata, and a
hostile-looking source path; tests also check node ID, text, metadata, and
source relationship invariants. Separate negative controls intentionally
trigger each observed sentinel, including NLTK model APIs.

These sentinels observe selected Python-level APIs only. They are not OS
containment and do not prove absence of native or direct syscalls, effects in
other processes, alternate import paths, other platforms, or arbitrary
consumer workflows. A passing probe is evidence for the exact inspected
process and conversion path, not a universal safety claim.

## Remaining release gates

The provisional consumer ranges remain broad:
`llama-index-core>=0.14.22,<0.15` and
`logseq-matryca-parser>=1.10.0,<1.11.0`. A local lock or evaluator does not
constrain package consumers. The qualified dependency graph, final source,
wheel, sdist, and metadata are not bound to release artifacts.

Still required before any exception or public release decision: final
commit/lock/production graph and artifact hash binding; consumer-resolution and
dependency-bound review; hosted Python 3.12/3.13 qualification; scheduled and
pre-publication expiry enforcement; trusted-publisher identity/workflow checks;
license and provenance review; fresh advisory reconciliation; explicit
maintainer acceptance of downstream exposure outside the adapter-only scope;
and a separate exact-artifact publication authorization. None is provided by
these local controls. The release remains blocked until those separate gates
are satisfied.
