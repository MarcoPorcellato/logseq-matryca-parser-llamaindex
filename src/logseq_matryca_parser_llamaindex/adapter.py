"""Convert Parser AST nodes to native LlamaIndex ``TextNode`` objects."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from llama_index.core.schema import NodeRelationship, RelatedNodeInfo, TextNode

from logseq_matryca_parser.logos_core import ASTVisitor, LogseqNode
from logseq_matryca_parser.synapse import build_synapse_metadata, page_source_node_id


def _flatten_nodes(nodes: list[LogseqNode]) -> list[LogseqNode]:
    """Return AST nodes in the Parser's depth-first visitor order."""
    flat: list[LogseqNode] = []
    for node in nodes:
        flat.append(node)
        if node.children:
            flat.extend(_flatten_nodes(node.children))
    return flat


class LlamaIndexVisitor(ASTVisitor):
    """Create native nodes and preserve Parser source/tree/sibling links."""

    def __init__(
        self,
        *,
        page_source_id: str | None = None,
        source_id_for_node: Callable[[LogseqNode], str] | None = None,
    ) -> None:
        self._page_source_id = page_source_id
        self._source_id_for_node = source_id_for_node
        self._nodes_by_id: dict[str, TextNode] = {}
        self._ordered_nodes: list[TextNode] = []

    def visit_node(self, node: LogseqNode) -> None:
        text_node = TextNode(
            id_=node.uuid,
            text=node.clean_text,
            metadata=build_synapse_metadata(node, source=node.source_path or ""),
        )

        source_id = self._page_source_id
        if self._source_id_for_node is not None:
            source_id = self._source_id_for_node(node)
        if source_id is not None:
            text_node.relationships[NodeRelationship.SOURCE] = RelatedNodeInfo(
                node_id=source_id
            )

        if node.parent_id:
            text_node.relationships[NodeRelationship.PARENT] = RelatedNodeInfo(
                node_id=node.parent_id
            )
            parent_node = self._nodes_by_id.get(node.parent_id)
            if parent_node is not None:
                child_relationships = parent_node.relationships.get(
                    NodeRelationship.CHILD, []
                )
                child_relationships.append(RelatedNodeInfo(node_id=node.uuid))
                parent_node.relationships[NodeRelationship.CHILD] = child_relationships

        if node.left_id:
            text_node.relationships[NodeRelationship.PREVIOUS] = RelatedNodeInfo(
                node_id=node.left_id
            )
            previous_node = self._nodes_by_id.get(node.left_id)
            if previous_node is not None:
                previous_node.relationships[NodeRelationship.NEXT] = RelatedNodeInfo(
                    node_id=node.uuid
                )

        self._nodes_by_id[node.uuid] = text_node
        self._ordered_nodes.append(text_node)

    def depart_node(self, node: LogseqNode) -> None:
        _ = node

    def get_nodes(self) -> list[TextNode]:
        return self._ordered_nodes


def to_llamaindex_nodes(
    nodes: list[LogseqNode],
    *,
    page_title: str | None = None,
    page_source_id: str | None = None,
) -> list[TextNode]:
    """Convert Parser nodes to LlamaIndex nodes while retaining graph links."""
    flat = _flatten_nodes(nodes)
    unique_paths = {node.source_path for node in flat if node.source_path}
    use_per_node_source = len(unique_paths) > 1
    source_ids_by_path: dict[str, str] = {}

    def source_id_for_node(node: LogseqNode) -> str:
        path_key = node.source_path or ""
        if path_key not in source_ids_by_path:
            title_seed = page_title or (Path(path_key).stem if path_key else "untitled")
            source_ids_by_path[path_key] = page_source_node_id(title_seed, path_key or None)
        return source_ids_by_path[path_key]

    resolved_source_id = page_source_id
    if resolved_source_id is None and not use_per_node_source:
        first_path = next(iter(unique_paths), None)
        resolved_source_id = page_source_node_id(page_title or "untitled", first_path)

    visitor = LlamaIndexVisitor(
        page_source_id=None if use_per_node_source else resolved_source_id,
        source_id_for_node=source_id_for_node if use_per_node_source else None,
    )
    for node in nodes:
        node.accept(visitor)
    return visitor.get_nodes()
