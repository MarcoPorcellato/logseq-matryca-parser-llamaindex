"""Distribution metadata and optional-import boundary checks."""

from __future__ import annotations

import email
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]


def _wheel_requirements() -> list[Requirement]:
    wheels = sorted((ROOT / "dist").glob("*.whl"))
    assert wheels, "Build the wheel before running distribution-contract tests"
    assert len(wheels) == 1, "Expected exactly one wheel in dist/"
    with zipfile.ZipFile(wheels[0]) as archive:
        metadata_path = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = email.message_from_bytes(archive.read(metadata_path))
    return [Requirement(value) for value in metadata.get_all("Requires-Dist", [])]


def test_companion_metadata_has_bounded_parser_and_llamaindex_ranges() -> None:
    requirements = _wheel_requirements()
    parser = next(req for req in requirements if req.name.lower() == "logseq-matryca-parser")
    llama = next(req for req in requirements if req.name.lower() == "llama-index-core")

    assert Version("1.10.0") in parser.specifier
    assert Version("1.10.99") in parser.specifier
    assert Version("1.9.99") not in parser.specifier
    assert Version("1.11.0") not in parser.specifier
    assert Version("0.14.22") in llama.specifier
    assert Version("0.14.99") in llama.specifier
    assert Version("0.15.0") not in llama.specifier


def test_parser_import_does_not_eagerly_load_companion() -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import logseq_matryca_parser; "
                "assert not any(name == 'logseq_matryca_parser_llamaindex' "
                "or name.startswith('logseq_matryca_parser_llamaindex.') "
                "for name in sys.modules)"
            ),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
