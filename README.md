# Logseq Matryca Parser — LlamaIndex companion

Optional adapter that converts the Parser's typed Logseq AST nodes into native
LlamaIndex `TextNode` objects while preserving source, parent/child, and sibling
relationships. The core Parser remains usable without LlamaIndex.

> **Status:** experimental development package. The public GitHub repository
> exists, but no package release is available yet. Compatibility,
> dependency-audit, and hosted-CI gates remain pending; do not treat this
> checkout as a supported release.

## Intended use

After a compatible Parser 1.10.x release and this companion's first release,
install the companion in the consuming project:

```bash
uv add logseq-matryca-parser-llamaindex
```

Then use the Parser bridge or companion API:

```python
from logseq_matryca_parser import SynapseAdapter

nodes = SynapseAdapter.to_llamaindex_nodes(ast_nodes)
```

`nodes` are real LlamaIndex `TextNode` instances. The companion keeps the
LlamaIndex dependency graph out of Parser's base installation. Parser's `ai`
extra continues to cover its separate LangChain integration; it does not
install this adapter.

### Data handling

The adapter itself performs no network requests, but exported nodes preserve
page text and metadata such as source paths and properties. Embedding, indexing,
or observability integrations may send that content to external services.
Review the selected provider's data handling, retention, and logging settings
before processing a private vault.

## Compatibility and security

The provisional manifest bounds Parser to `>=1.10.0,<1.11.0` and
`llama-index-core` to `>=0.14.22,<0.15`. The Parser 1.10.0 lower bound is not
yet available from the package registry, so minimum-version resolution and a
reproducible production lock are not yet qualified. Do not broaden either range
without testing the new boundary releases.

The companion has an independent dependency audit obligation. Removing NLTK
from the Parser dependency graph does not establish that this optional
LlamaIndex graph is free of NLTK advisories. Reconcile current advisory records
and complete a clean audit before any release; do not add an unapproved waiver.

Local experimental security-control behavior and its limits are documented in
[`docs/SECURITY_EXCEPTION_CONTROLS.md`](docs/SECURITY_EXCEPTION_CONTROLS.md).
These controls are unpublished and inactive; they do not authorize a waiver or
release.

## Local development

This repository intentionally has no production lock or release workflow yet:
the Parser minimum is unreleased, so a registry-resolved lock cannot currently
be generated honestly. Once that dependency is available, the next gate is to
generate and review `uv.lock`, then add Python 3.12/3.13 hosted CI with locked
tests, wheel metadata checks, and an audit of the exact production export.

The adapter tests require the Parser source distribution and `llama-index-core`
to be installed. Run the standard project checks after the lock and CI gate are
established:

```bash
uv sync --locked
uv build
uv run pytest -q
uv run ruff check .
```

The wheel build intentionally precedes `pytest`: the distribution-contract test
reads the wheel's generated `METADATA` file from `dist/`.
