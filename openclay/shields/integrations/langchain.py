"""
LangChain / LangGraph Integration for OpenClay.

Provides a single callback handler that intercepts LLM calls, tool usage,
and responses to enforce security at every stage of a LangChain pipeline.

Requires: langchain-core >= 0.1.0
    pip install langchain-core

Usage:
    from openclay import Shield
    from openclay.integrations.langchain import OpenClayCallbackHandler

    shield = Shield.balanced(
        sensitive_terms=["API_KEY=sk-abc123"],
        honeypot_tokens=["CANARY_TRAP_XYZ"],
    )

    handler = OpenClayCallbackHandler(shield=shield)

    # LangChain — attach to any chain/agent
    chain.invoke(input, config={"callbacks": [handler]})

    # LangGraph — attach to graph execution
    graph.invoke(state, config={"callbacks": [handler]})
"""

import logging
from typing import Any, Dict, List, Optional, Sequence, Union
from uuid import UUID

logger = logging.getLogger("openclay")

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    from langchain_core.messages import BaseMessage

    _HAS_LANGCHAIN = True
except ImportError:
    _HAS_LANGCHAIN = False


def _require_langchain():
    if not _HAS_LANGCHAIN:
        raise ImportError(
            "LangChain integration requires langchain-core >= 0.1.0. "
            "Install with: pip install langchain-core"
        )


import contextvars

_threat_var: contextvars.ContextVar[float] = contextvars.ContextVar(
    "openclay_threat", default=0.0
)

if _HAS_LANGCHAIN:
    _BaseClass = BaseCallbackHandler
else:
    _BaseClass = object

class OpenClayCallbackHandler(_BaseClass):
    """
    LangChain callback handler that enforces OpenClay at every stage.

    Intercepts:
        on_llm_start / on_chat_model_start → protect_input()
        on_tool_start                      → protect_tool_call()
        on_llm_end                         → protect_output()

    Blocked events are logged and optionally raise an exception to halt
    the chain via the `raise_on_block` parameter.
    """

    def __init__(
        self,
        shield,
        system_context: str = "",
        raise_on_block: bool = True,
        on_block: Any = None,
        allowed_tools: Optional[List[str]] = None,
    ):
        """
        Args:
            shield: Shield or AsyncShield instance
            system_context: System prompt for protect_input context
            raise_on_block: If True, raise ValueError on blocked input/output
            on_block: Optional callback(result_dict) fired on any block event
            allowed_tools: Whitelist of tool names for protect_tool_call
        """
        self.shield = shield
        self.system_context = system_context
        self.raise_on_block = raise_on_block
        self.on_block = on_block
        self.allowed_tools = allowed_tools

        # Stats
        self.stats = {
            "inputs_scanned": 0,
            "inputs_blocked": 0,
            "tools_scanned": 0,
            "tools_blocked": 0,
            "outputs_scanned": 0,
            "outputs_blocked": 0,
        }

    def _handle_block(self, result: Dict, stage: str):
        """Handle a blocked event — log, callback, optionally raise."""
        logger.warning(
            "OpenClay BLOCKED at %s: reason=%s",
            stage,
            result.get("reason", "unknown"),
        )
        if self.on_block:
            try:
                self.on_block(result)
            except Exception:
                pass

        if self.raise_on_block:
            raise ValueError(
                f"OpenClay blocked at {stage}: {result.get('reason', 'unknown')}"
            )

    # ── LLM Start (Input Protection) ──

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: Optional[UUID] = None,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Scan prompts before they reach the LLM."""
        for prompt in prompts:
            self.stats["inputs_scanned"] += 1
            result = self.shield.protect_input(prompt, self.system_context)
            _threat_var.set(result.get("threat_level", 0.0))

            if result.get("blocked"):
                self.stats["inputs_blocked"] += 1
                self._handle_block(result, "on_llm_start")

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: Optional[UUID] = None,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Scan chat messages before they reach the model."""
        for message_list in messages:
            for msg in message_list:
                # Extract text content from BaseMessage or dict
                if hasattr(msg, "content"):
                    text = str(msg.content)
                elif isinstance(msg, dict):
                    text = str(msg.get("content", ""))
                else:
                    text = str(msg)

                if not text.strip():
                    continue

                self.stats["inputs_scanned"] += 1
                result = self.shield.protect_input(text, self.system_context)
                _threat_var.set(result.get("threat_level", 0.0))

                if result.get("blocked"):
                    self.stats["inputs_blocked"] += 1
                    self._handle_block(result, "on_chat_model_start")

    # ── Tool Start (Agentic Protection) ──

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Optional[UUID] = None,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """Scan tool arguments before tool execution."""
        tool_name = serialized.get("name", "unknown_tool")

        self.stats["tools_scanned"] += 1

        # Parse input_str as JSON if possible
        import json
        try:
            arguments = json.loads(input_str)
        except (json.JSONDecodeError, TypeError):
            arguments = {"raw_input": input_str}

        result = self.shield.protect_tool_call(
            tool_name=tool_name,
            arguments=arguments,
            allowed_tools=self.allowed_tools,
        )

        if result.get("blocked"):
            self.stats["tools_blocked"] += 1
            self._handle_block(result, "on_tool_start")

    # ── LLM End (Output Protection) ──

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Optional[UUID] = None,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> None:
        """Scan LLM output for data leaks and prompt leakage."""
        # Extract text from LLMResult
        try:
            for generation_list in response.generations:
                for generation in generation_list:
                    text = generation.text if hasattr(generation, "text") else str(generation)
                    if not text.strip():
                        continue

                    self.stats["outputs_scanned"] += 1
                    result = self.shield.protect_output(
                        model_output=text,
                        input_threat_level=_threat_var.get(),
                    )

                    if result.get("blocked"):
                        self.stats["outputs_blocked"] += 1
                        self._handle_block(result, "on_llm_end")
        except Exception as e:
            logger.warning("OpenClay on_llm_end extraction failed: %s", e)

    # ── Utility ──

    def get_stats(self) -> Dict:
        """Return scan statistics."""
        return self.stats.copy()
