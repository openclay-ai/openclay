"""
LlamaIndex Integration for OpenClay.

Provides a node postprocessor that scans retrieved RAG chunks for
prompt injection attacks before they enter the LLM context window.

Requires: llama-index-core >= 0.10.0
    pip install llama-index-core

Usage:
    from openclay import Shield
    from openclay.integrations.llamaindex import OpenClayRetrieverFilter

    shield = Shield.balanced()
    postprocessor = OpenClayRetrieverFilter(shield=shield)

    query_engine = index.as_query_engine(
        node_postprocessors=[postprocessor]
    )
    response = query_engine.query("What is our revenue?")
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("openclay")

try:
    from llama_index.core.postprocessor.types import BaseNodePostprocessor
    from llama_index.core.schema import NodeWithScore, QueryBundle

    _HAS_LLAMAINDEX = True
except ImportError:
    _HAS_LLAMAINDEX = False


def _require_llamaindex():
    if not _HAS_LLAMAINDEX:
        raise ImportError(
            "LlamaIndex integration requires llama-index-core >= 0.10.0. "
            "Install with: pip install llama-index-core"
        )


class OpenClayRetrieverFilter:
    """
    LlamaIndex node postprocessor that scans RAG chunks for injection.

    Poisoned RAG documents are a major attack vector — an adversary
    plants malicious text in a knowledge base, and it gets retrieved
    into the LLM's context. This filter catches those before they
    reach the model.

    Blocked nodes are removed from the results (not passed to the LLM).
    """

    def __init__(
        self,
        shield,
        system_context: str = "",
        on_block: Any = None,
        threat_threshold: float = 0.5,
    ):
        """
        Args:
            shield: Shield instance
            system_context: System prompt for protect_input context
            on_block: Optional callback(node, result) on blocked node
            threat_threshold: Minimum threat_level to filter a node
        """
        _require_llamaindex()
        self.shield = shield
        self.system_context = system_context
        self.on_block = on_block
        self.threat_threshold = threat_threshold

        self.stats = {
            "nodes_scanned": 0,
            "nodes_blocked": 0,
        }

    def _postprocess_nodes(
        self,
        nodes: List[Any],
        query_bundle: Optional[Any] = None,
    ) -> List[Any]:
        """
        Filter retrieved nodes through OpenClay.

        Nodes whose content triggers a block or exceeds the threat
        threshold are removed from the list before they reach the LLM.
        """
        safe_nodes = []

        for node in nodes:
            # Extract text from NodeWithScore or plain Node
            if hasattr(node, "node") and hasattr(node.node, "get_content"):
                text = node.node.get_content()
            elif hasattr(node, "get_content"):
                text = node.get_content()
            elif hasattr(node, "text"):
                text = node.text
            else:
                text = str(node)

            if not text.strip():
                safe_nodes.append(node)
                continue

            self.stats["nodes_scanned"] += 1
            result = self.shield.protect_input(text, self.system_context)

            if result.get("blocked") or result.get("threat_level", 0.0) >= self.threat_threshold:
                self.stats["nodes_blocked"] += 1
                logger.warning(
                    "OpenClay filtered RAG node: reason=%s, threat=%.3f",
                    result.get("reason", "threshold"),
                    result.get("threat_level", 0.0),
                )

                if self.on_block:
                    try:
                        self.on_block(node, result)
                    except Exception:
                        pass
            else:
                safe_nodes.append(node)

        return safe_nodes

    # Alias for LlamaIndex's expected method name
    def postprocess_nodes(
        self,
        nodes: List[Any],
        query_bundle: Optional[Any] = None,
    ) -> List[Any]:
        """LlamaIndex standard interface."""
        return self._postprocess_nodes(nodes, query_bundle)

    def get_stats(self) -> Dict:
        """Return scan statistics."""
        return self.stats.copy()


# If LlamaIndex is available, inherit properly
if _HAS_LLAMAINDEX:
    OpenClayRetrieverFilter.__bases__ = (BaseNodePostprocessor,)
