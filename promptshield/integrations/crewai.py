"""
CrewAI Integration for PromptShield.

Provides a step_callback interceptor that scans inter-agent messages
and tool arguments during CrewAI multi-agent execution.

Requires: crewai >= 0.30.0
    pip install crewai

Usage:
    from promptshield import Shield
    from promptshield.integrations.crewai import PromptShieldCrewInterceptor

    shield = Shield.balanced(
        sensitive_terms=["CONFIDENTIAL_PROJECT"],
        honeypot_tokens=["AGENT_TRAP_TOKEN"],
    )

    interceptor = PromptShieldCrewInterceptor(shield=shield)

    # Attach to individual agents
    agent = Agent(
        role="researcher",
        step_callback=interceptor.step_callback,
    )

    # Or attach at crew level
    crew = Crew(
        agents=[agent],
        tasks=[task],
        step_callback=interceptor.step_callback,
    )
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("promptshield")

try:
    from crewai import Agent

    _HAS_CREWAI = True
except ImportError:
    _HAS_CREWAI = False


def _require_crewai():
    if not _HAS_CREWAI:
        raise ImportError(
            "CrewAI integration requires crewai >= 0.30.0. "
            "Install with: pip install crewai"
        )


class PromptShieldCrewInterceptor:
    """
    CrewAI step_callback interceptor for multi-agent security.

    Intercepts every agent step and applies the appropriate shield:

    Steps with tool usage  → protect_tool_call()
    Steps with agent output → protect_output()

    Designed to catch:
    - Malicious tool arguments injected between agents
    - Sensitive data leaking through delegation chains
    - Honeypot traps triggered by compromised agents
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
            shield: Shield instance
            system_context: System prompt for protect_input context
            raise_on_block: If True, raise ValueError to halt crew execution
            on_block: Optional callback(step_output, result) on block
            allowed_tools: Whitelist of allowed tool names
        """
        self.shield = shield
        self.system_context = system_context
        self.raise_on_block = raise_on_block
        self.on_block = on_block
        self.allowed_tools = allowed_tools

        self.stats = {
            "steps_scanned": 0,
            "tools_scanned": 0,
            "tools_blocked": 0,
            "outputs_scanned": 0,
            "outputs_blocked": 0,
        }

    def _handle_block(self, result: Dict, step_output: Any, stage: str):
        """Handle a blocked event."""
        logger.warning(
            "PromptShield BLOCKED CrewAI %s: reason=%s",
            stage,
            result.get("reason", "unknown"),
        )
        if self.on_block:
            try:
                self.on_block(step_output, result)
            except Exception:
                pass

        if self.raise_on_block:
            raise ValueError(
                f"PromptShield blocked CrewAI {stage}: {result.get('reason', 'unknown')}"
            )

    def step_callback(self, step_output: Any) -> None:
        """
        CrewAI step_callback — called after each agent step.

        Automatically detects step type (AgentAction vs AgentFinish)
        and applies the appropriate shield scan.

        Args:
            step_output: CrewAI step output (AgentAction, AgentFinish, or ToolResult)
        """
        self.stats["steps_scanned"] += 1

        try:
            # Detect step type by attribute inspection
            # (avoids hard ImportError on crewai internals)

            step_type = type(step_output).__name__

            if step_type == "AgentAction" or hasattr(step_output, "tool"):
                # Tool usage step → protect_tool_call
                self._scan_tool_step(step_output)

            elif step_type == "AgentFinish" or hasattr(step_output, "return_values"):
                # Agent finished → protect_output
                self._scan_finish_step(step_output)

            elif step_type == "ToolResult" or hasattr(step_output, "result"):
                # Tool result → protect_output on result content
                self._scan_tool_result(step_output)

            else:
                # Unknown step type — scan as text
                text = str(step_output)
                if text.strip():
                    self._scan_text_output(text, step_output)

        except ValueError:
            raise  # Re-raise block exceptions
        except Exception as e:
            logger.warning("PromptShield CrewAI step scan failed: %s", e)

    def _scan_tool_step(self, step):
        """Scan tool arguments from an AgentAction step."""
        tool_name = getattr(step, "tool", "unknown_tool")
        tool_input = getattr(step, "tool_input", "")

        # Parse tool_input
        import json
        if isinstance(tool_input, str):
            try:
                arguments = json.loads(tool_input)
            except (json.JSONDecodeError, TypeError):
                arguments = {"raw_input": tool_input}
        elif isinstance(tool_input, dict):
            arguments = tool_input
        else:
            arguments = {"raw_input": str(tool_input)}

        self.stats["tools_scanned"] += 1
        result = self.shield.protect_tool_call(
            tool_name=str(tool_name),
            arguments=arguments,
            allowed_tools=self.allowed_tools,
        )

        if result.get("blocked"):
            self.stats["tools_blocked"] += 1
            self._handle_block(result, step, "tool_call")

    def _scan_finish_step(self, step):
        """Scan final output from an AgentFinish step."""
        return_values = getattr(step, "return_values", {})
        if isinstance(return_values, dict):
            text = return_values.get("output", str(return_values))
        else:
            text = str(return_values)

        self._scan_text_output(text, step)

    def _scan_tool_result(self, step):
        """Scan tool result content."""
        result_text = getattr(step, "result", str(step))
        self._scan_text_output(str(result_text), step)

    def _scan_text_output(self, text: str, step_output: Any):
        """Scan arbitrary text output."""
        if not text.strip():
            return

        self.stats["outputs_scanned"] += 1
        result = self.shield.protect_output(model_output=text)

        if result.get("blocked"):
            self.stats["outputs_blocked"] += 1
            self._handle_block(result, step_output, "output")

    def get_stats(self) -> Dict:
        """Return scan statistics."""
        return self.stats.copy()
