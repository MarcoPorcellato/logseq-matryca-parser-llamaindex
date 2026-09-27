from __future__ import annotations

from llama_index.core.schema import NodeRelationship, TextNode
from logseq_matryca_parser_llamaindex import to_llamaindex_nodes

from logseq_matryca_parser.logos_core import LogseqNode
from logseq_matryca_parser.synapse import SynapseAdapter, page_source_node_id


def _node(
    node_id: str,
    text: str,
    *,
    parent_id: str | None = None,
    left_id: str | None = None,
    indent_level: int = 0,
    path: list[str] | None = None,
    source_path: str | None = None,
    properties: dict[str, object] | None = None,
    task_status: str | None = None,
    children: list[LogseqNode] | None = None,
) -> LogseqNode:
    return LogseqNode(
        uuid=node_id,
        content=f"{text} source content",
        clean_text=text,
        indent_level=indent_level,
        parent_id=parent_id,
        left_id=left_id,
        path=path or [],
        source_path=source_path,
        properties=properties or {},
        task_status=task_status,
        children=children or [],
    )


def _related_ids(node: TextNode, relation: NodeRelationship) -> list[str]:
    related = node.relationships[relation]
    if isinstance(related, list):
        return [item.node_id for item in related]
    return [related.node_id]


def test_native_nodes_preserve_metadata_order_and_topology() -> None:
    source_path = "/vault/pages/Root.md"
    leaf = _node(
        "leaf-id",
        "Leaf clean",
        parent_id="child-a",
        indent_level=2,
        path=["Root", "Child A", "Leaf"],
        source_path=source_path,
        task_status="TODO",
    )
    child_a = _node(
        "child-a",
        "Child A clean",
        parent_id="root-id",
        indent_level=1,
        path=["Root", "Child A"],
        source_path=source_path,
        properties={"tags": ["alpha", "beta"]},
        children=[leaf],
    )
    child_b = _node(
        "child-b",
        "Child B clean",
        parent_id="root-id",
        left_id="child-a",
        indent_level=1,
        path=["Root", "Child B"],
        source_path=source_path,
    )
    root = _node(
        "root-id",
        "Root clean",
        path=["Root"],
        source_path=source_path,
        properties={"topic": "alpha"},
        children=[child_a, child_b],
    )

    nodes = to_llamaindex_nodes([root], page_source_id="explicit-page-id")

    assert all(isinstance(node, TextNode) for node in nodes)
    assert [node.id_ for node in nodes] == ["root-id", "child-a", "leaf-id", "child-b"]
    assert [node.text for node in nodes] == [
        "Root clean",
        "Child A clean",
        "Leaf clean",
        "Child B clean",
    ]
    by_id = {node.id_: node for node in nodes}
    assert by_id["root-id"].metadata["topic"] == "alpha"
    assert by_id["child-a"].metadata["tags"] == "alpha, beta"
    assert by_id["leaf-id"].metadata["task_status"] == "TODO"
    assert by_id["child-a"].metadata["path"] == "Root > Child A"
    assert all(
        _related_ids(node, NodeRelationship.SOURCE) == ["explicit-page-id"]
        for node in nodes
    )
    assert _related_ids(by_id["child-a"], NodeRelationship.PARENT) == ["root-id"]
    assert _related_ids(by_id["leaf-id"], NodeRelationship.PARENT) == ["child-a"]
    assert _related_ids(by_id["root-id"], NodeRelationship.CHILD) == ["child-a", "child-b"]
    assert _related_ids(by_id["child-a"], NodeRelationship.CHILD) == ["leaf-id"]
    assert _related_ids(by_id["child-b"], NodeRelationship.PREVIOUS) == ["child-a"]
    assert _related_ids(by_id["child-a"], NodeRelationship.NEXT) == ["child-b"]


def test_empty_input_returns_no_nodes() -> None:
    assert to_llamaindex_nodes([]) == []


def test_same_basename_different_paths_have_distinct_sources() -> None:
    first = _node("first-page", "First", source_path="/vault/a/Journal.md")
    second = _node("second-page", "Second", source_path="/vault/b/Journal.md")

    nodes = to_llamaindex_nodes([first, second])

    source_ids = [
        _related_ids(node, NodeRelationship.SOURCE)[0]
        for node in nodes
    ]
    assert source_ids == [
        page_source_node_id("Journal", "/vault/a/Journal.md"),
        page_source_node_id("Journal", "/vault/b/Journal.md"),
    ]
    assert len(set(source_ids)) == 2


def test_explicit_source_id_preserves_single_and_mixed_page_behavior() -> None:
    single = _node("single", "Single", source_path="/vault/pages/Journal.md")
    single_node = to_llamaindex_nodes(
        [single], page_title="Journal", page_source_id="manual-source"
    )[0]
    assert _related_ids(single_node, NodeRelationship.SOURCE) == ["manual-source"]

    first = _node("page-a", "A", source_path="/vault/a/Journal.md")
    second = _node("page-b", "B", source_path="/vault/b/Journal.md")
    mixed = to_llamaindex_nodes(
        [first, second], page_title="Journal", page_source_id="manual-source"
    )
    assert [
        _related_ids(node, NodeRelationship.SOURCE)[0]
        for node in mixed
    ] == [
        page_source_node_id("Journal", "/vault/a/Journal.md"),
        page_source_node_id("Journal", "/vault/b/Journal.md"),
    ]


def test_out_of_batch_links_do_not_create_reciprocals() -> None:
    child = _node("child", "Child", parent_id="outside-parent")
    sibling = _node("sibling", "Sibling", left_id="outside-left")

    nodes = to_llamaindex_nodes([child, sibling], page_source_id="page-id")

    by_id = {node.id_: node for node in nodes}
    assert _related_ids(by_id["child"], NodeRelationship.PARENT) == ["outside-parent"]
    assert _related_ids(by_id["sibling"], NodeRelationship.PREVIOUS) == ["outside-left"]
    assert all(NodeRelationship.CHILD not in node.relationships for node in nodes)
    assert all(NodeRelationship.NEXT not in node.relationships for node in nodes)


def test_parser_shim_returns_real_native_nodes() -> None:
    source_path = "/vault/pages/Journal.md"
    parser_node = _node("shim-node", "Shim clean", source_path=source_path)

    nodes = SynapseAdapter.to_llamaindex_nodes([parser_node])

    assert len(nodes) == 1
    assert isinstance(nodes[0], TextNode)
    assert nodes[0].id_ == "shim-node"
    assert _related_ids(nodes[0], NodeRelationship.SOURCE) == [
        page_source_node_id("untitled", source_path)
    ]
