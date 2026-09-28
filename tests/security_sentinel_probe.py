"""Fresh-process sentinel harness for bounded import/conversion observations."""

from __future__ import annotations

import builtins
import io
import os
import socket
import subprocess
import sys
from collections.abc import Callable
from typing import Any


class SentinelViolation(RuntimeError):
    """Raised when an observed operation crosses a probe boundary."""


_VIOLATIONS: list[str] = []


def _violate(label: str) -> None:
    _VIOLATIONS.append(label)
    raise SentinelViolation(f"SENTINEL_{label}")


def _deny(label: str) -> Callable[..., Any]:
    def denied(*_args: object, **_kwargs: object) -> Any:
        _violate(label)

    return denied


def _arm(*, reads: bool, writes: bool, model: bool) -> None:
    sys.dont_write_bytecode = True
    real_builtin_open = builtins.open
    real_io_open = io.open
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def guarded_mode(mode: object) -> None:
        if not isinstance(mode, str):
            mode = "r"
        if writes and any(flag in mode for flag in "wax+"):
            _violate("WRITE")
        if reads and "r" in mode:
            _violate("READ")

    def builtin_open(file: object, mode: str = "r", *args: object, **kwargs: object) -> Any:
        guarded_mode(mode)
        return real_builtin_open(file, mode, *args, **kwargs)

    def io_open(
        file: object, mode: str = "r", *args: object, **kwargs: object
    ) -> Any:
        guarded_mode(mode)
        return real_io_open(file, mode, *args, **kwargs)

    real_os_open = os.open

    def os_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if writes and flags & write_flags:
            _violate("WRITE")
        if reads and not flags & write_flags:
            _violate("READ")
        return real_os_open(path, flags, *args, **kwargs)

    builtins.open = builtin_open
    io.open = io_open
    os.open = os_open
    socket.socket.connect = _deny("NETWORK")  # type: ignore[method-assign]
    socket.create_connection = _deny("NETWORK")  # type: ignore[assignment]
    subprocess.Popen = _deny("PROCESS")  # type: ignore[assignment,misc]
    os.system = _deny("PROCESS")  # type: ignore[assignment]
    for process_name in ("posix_spawn", "posix_spawnp", "execv", "execve", "spawnv"):
        if hasattr(os, process_name):
            setattr(os, process_name, _deny("PROCESS"))

    if model:
        import nltk.classify.maxent
        import nltk.data
        import nltk.parse.transitionparser
        import nltk.tag.perceptron

        nltk.data.load = _deny("MODEL_LOAD")  # type: ignore[assignment]
        nltk.data.find = _deny("MODEL_LOAD")  # type: ignore[assignment]
        nltk.parse.transitionparser.TransitionParser.train = _deny("MODEL_API")  # type: ignore[method-assign]
        nltk.parse.transitionparser.TransitionParser.parse = _deny("MODEL_API")  # type: ignore[method-assign]
        nltk.tag.perceptron.AveragedPerceptron.save = _deny("MODEL_API")  # type: ignore[method-assign]
        nltk.tag.perceptron.AveragedPerceptron.load = _deny("MODEL_API")  # type: ignore[method-assign]
        nltk.tag.perceptron.PerceptronTagger.save_to_json = _deny("MODEL_API")  # type: ignore[method-assign]
        nltk.classify.maxent.save_maxent_params = _deny("MODEL_API")  # type: ignore[assignment]


def _fixture() -> Any:
    from logseq_matryca_parser.logos_core import LogseqNode

    return LogseqNode(
        uuid="side-effect-probe-node",
        content="raw content {{embed [[hostile]]}}",
        clean_text="clean text {{config secrets}}",
        indent_level=0,
        parent_id=None,
        left_id=None,
        path=["Hostile {{macro}}", "../outside"],
        source_path="../../outside/{{ hostile }}\nsource.md",
        properties={"hostile": "{{include /etc/passwd}}", "path": "../../outside"},
        task_status=None,
        children=[],
    )


def _convert(mode: str) -> None:
    from llama_index.core.schema import NodeRelationship

    node = _fixture()
    empty = mode.startswith("empty-")
    use_shim = mode.endswith("-shim")
    nodes: list[Any] = []
    if use_shim:
        from logseq_matryca_parser.synapse import SynapseAdapter

        nodes = SynapseAdapter.to_llamaindex_nodes([] if empty else [node])
    else:
        from logseq_matryca_parser_llamaindex import to_llamaindex_nodes

        nodes = to_llamaindex_nodes([] if empty else [node])
    if empty:
        assert nodes == []
    else:
        assert len(nodes) == 1
        assert nodes[0].id_ == "side-effect-probe-node"
        assert nodes[0].text == "clean text {{config secrets}}"
        assert nodes[0].metadata["hostile"] == "{{include /etc/passwd}}"
        assert NodeRelationship.SOURCE in nodes[0].relationships


def _run(argv: list[str]) -> int:
    if not argv:
        print("probe mode required", file=sys.stderr)
        return 2
    mode = argv[0]
    try:
        if mode == "import-companion":
            _arm(reads=False, writes=True, model=False)
            import logseq_matryca_parser_llamaindex

            _ = logseq_matryca_parser_llamaindex
        elif mode == "import-schema":
            _arm(reads=False, writes=True, model=False)
            import llama_index.core.schema

            _ = llama_index.core.schema
        elif mode == "import-shim":
            _arm(reads=False, writes=True, model=False)
            from logseq_matryca_parser.synapse import SynapseAdapter

            _ = SynapseAdapter.to_llamaindex_nodes([_fixture()])
        elif mode in {
            "convert-empty-companion",
            "convert-nodes-companion",
            "convert-empty-shim",
            "convert-nodes-shim",
        }:
            import llama_index.core.schema
            import logseq_matryca_parser.logos_core
            import logseq_matryca_parser.synapse
            import nltk.classify.maxent
            import nltk.data
            import nltk.parse.transitionparser
            import nltk.tag.perceptron

            import logseq_matryca_parser_llamaindex

            _ = (llama_index.core.schema, logseq_matryca_parser.logos_core)
            _ = (logseq_matryca_parser.synapse, logseq_matryca_parser_llamaindex)
            _arm(reads=True, writes=True, model=True)
            _convert(mode.removeprefix("convert-"))
        elif mode.startswith("negative-"):
            import nltk.classify.maxent
            import nltk.data
            import nltk.parse.transitionparser
            import nltk.tag.perceptron

            _arm(
                reads=True,
                writes=True,
                model=mode not in {"negative-model-api", "negative-model-read-api"},
            )
            if mode == "negative-write":
                with builtins.open("probe-output", "w", encoding="utf-8"):
                    pass
            elif mode == "negative-caught-write":
                try:
                    with builtins.open("probe-output", "w", encoding="utf-8"):
                        pass
                except SentinelViolation:
                    pass
            elif mode == "negative-read":
                with builtins.open("/etc/passwd", encoding="utf-8"):
                    pass
            elif mode == "negative-network":
                socket.create_connection(("example.invalid", 443), timeout=0.01)
            elif mode == "negative-process":
                subprocess.Popen([sys.executable, "-c", "pass"])
            elif mode == "negative-model-api":
                nltk.tag.perceptron.AveragedPerceptron().save("probe-model.json")
            elif mode == "negative-model-read-api":
                nltk.tag.perceptron.AveragedPerceptron().load("probe-model.json")
            elif mode == "negative-model-load":
                nltk.data.load("tokenizers/punkt/english.pickle")
            else:
                print(f"unknown negative control: {mode}", file=sys.stderr)
                return 2
            if _VIOLATIONS:
                print(f"SENTINEL_{_VIOLATIONS[0]}", file=sys.stderr)
                return 73
            print("SENTINEL_NOT_TRIGGERED", file=sys.stderr)
            return 1
        else:
            print(f"unknown probe mode: {mode}", file=sys.stderr)
            return 2
    except SentinelViolation as exc:
        print(str(exc), file=sys.stderr)
        return 73
    except Exception as exc:  # surfaced by the parent assertion with exact context
        print(f"PROBE_ERROR:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 1
    if _VIOLATIONS:
        print(f"SENTINEL_{_VIOLATIONS[0]}", file=sys.stderr)
        return 73
    print(f"PROBE_PASS:{mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run(sys.argv[1:]))
