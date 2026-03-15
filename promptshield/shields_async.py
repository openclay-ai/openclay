"""
Async Shield — Non-blocking wrapper for production async frameworks.

Usage:
    from promptshield import AsyncShield

    shield = AsyncShield.balanced()

    result = await shield.aprotect_input(user_input, system_prompt)
    result = await shield.aprotect_output(model_output, canary=canary)
"""

import asyncio
from typing import Any, Callable, Dict, List, Optional

from .shields import Shield


class AsyncShield(Shield):
    """
    Async-enabled security shield.

    Wraps all blocking operations (ML inference, pattern matching)
    using asyncio.to_thread() so they never block the event loop.

    Inherits all configuration from Shield — same presets, same components.

    Examples:
        # Use presets (same as Shield)
        shield = AsyncShield.fast()
        shield = AsyncShield.balanced()
        shield = AsyncShield.secure()

        # Async usage
        result = await shield.aprotect_input("user text", "system prompt")
        result = await shield.aprotect_output("model output", canary=canary)
        result = await shield.aprotect_tool_call("tool_name", {"key": "value"})
    """

    async def aprotect_input(
        self,
        user_input: str,
        system_context: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        **context,
    ) -> Dict:
        """
        Async version of protect_input().

        Runs the full protection pipeline in a thread pool
        so ML inference and pattern matching don't block the event loop.

        Args:
            user_input: User's input text
            system_context: System prompt / context
            user_id: User identifier (for rate limiting)
            session_id: Session identifier (for tracking)
            **context: Additional context

        Returns:
            Same dict as protect_input()
        """
        return await asyncio.to_thread(
            self.protect_input,
            user_input,
            system_context,
            user_id=user_id,
            session_id=session_id,
            **context,
        )

    async def aprotect_output(
        self,
        model_output: str,
        canary: Optional[Dict] = None,
        user_id: Optional[str] = None,
        user_input: Optional[str] = None,
        enforce_embeddings: bool = False,
        forbidden_vectors: Optional[List[str]] = None,
        vector_db_client: Optional[Callable[[List[float]], float]] = None,
        input_threat_level: float = 0.0,
        **context,
    ) -> Dict:
        """
        Async version of protect_output().

        Args:
            model_output: LLM output text
            canary: Canary data from protect_input
            user_id: User identifier
            user_input: Original user input (for PII context)
            enforce_embeddings: Enable embedding guard (DLP)
            forbidden_vectors: List of sensitive strings to match against
            vector_db_client: BYO-VDB callback for enterprise-scale DLP
            input_threat_level: Threat score from protect_input (lowers thresholds)
            **context: Additional context

        Returns:
            Same dict as protect_output()
        """
        return await asyncio.to_thread(
            self.protect_output,
            model_output,
            canary=canary,
            user_id=user_id,
            user_input=user_input,
            enforce_embeddings=enforce_embeddings,
            forbidden_vectors=forbidden_vectors,
            vector_db_client=vector_db_client,
            input_threat_level=input_threat_level,
            **context,
        )

    async def aprotect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        allowed_tools: Optional[List[str]] = None,
        **context,
    ) -> Dict:
        """
        Async version of protect_tool_call().

        Validates MCP/Agent tool call arguments without blocking the event loop.
        Essential for async agentic frameworks (LangGraph, CrewAI).

        Args:
            tool_name: Name of the tool being called
            arguments: JSON arguments being sent to the tool
            allowed_tools: Whitelist of permitted tool names
            **context: Additional context

        Returns:
            Same dict as protect_tool_call()
        """
        return await asyncio.to_thread(
            self.protect_tool_call,
            tool_name,
            arguments,
            allowed_tools=allowed_tools,
            **context,
        )

    async def aprotect_stream_chunk(
        self,
        chunk: str,
        buffer: Optional[str] = None,
        canary: Optional[Dict] = None,
        **context,
    ) -> Dict:
        """
        Async check a single streaming chunk.

        For streaming LLM responses — checks each chunk for canary leaks
        and PII without blocking the event loop.

        Args:
            chunk: Current text chunk from stream
            buffer: Accumulated text so far (for canary detection)
            canary: Canary data from protect_input
            **context: Additional context

        Returns:
            {"blocked": bool, "text": str, "reason": str|None}
        """
        full_text = (buffer or "") + chunk

        # Canary check (fast, can run sync)
        if canary and self.config["canary"]:
            if self.config["canary_mode"] == "crypto":
                from .security.canary_crypto import verify_canary_leak
                is_leaked, reason = verify_canary_leak(full_text, canary)
                if is_leaked:
                    return {
                        "blocked": True,
                        "text": "",
                        "reason": f"canary_leak:{reason}",
                    }
            else:
                from .methods import detect_canary
                if detect_canary(full_text, canary.get("canary", "")):
                    return {
                        "blocked": True,
                        "text": "",
                        "reason": "canary_leak",
                    }

        # PII check on chunk (run in thread if enabled)
        if self.config["pii_detection"]:
            result = await asyncio.to_thread(
                self._scan_chunk_pii, full_text
            )
            if result:
                return result

        return {"blocked": False, "text": chunk, "reason": None}

    def _scan_chunk_pii(self, text: str) -> Optional[Dict]:
        """Scan a chunk for PII (sync helper for thread pool)."""
        from .methods import pii_scan

        findings = pii_scan(text)
        if findings:
            return {
                "blocked": True,
                "text": "",
                "reason": "pii_in_stream",
                "findings": findings,
            }
        return None

    async def protect_stream(
        self,
        async_generator,
        canary: Optional[Dict] = None,
        **context,
    ):
        """
        Wrap an async text generator to automatically scan for threats mid-generation.
        Raises StreamBlockedError if a threat is detected.
        
        Args:
            async_generator: Async iterable yielding strings
            canary: Canary data from protect_input
            **context: Additional context
            
        Yields:
            str: The safe chunks
            
        Raises:
            StreamBlockedError: If the stream contains restricted content (e.g. PII leak, Canary leak)
        """
        buffer = ""
        async for chunk in async_generator:
            result = await self.aprotect_stream_chunk(chunk, buffer, canary, **context)
            if result.get("blocked"):
                if getattr(self, "webhook", None):
                    # Ensure webhook is triggered on blocked streams too
                    self.webhook.notify(result, None)
                from .exceptions import StreamBlockedError
                raise StreamBlockedError(reason=result["reason"], result_dict=result)
            
            buffer += chunk
            yield result["text"]
