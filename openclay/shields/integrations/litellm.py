"""
LiteLLM Integration for OpenClay.

Provides a custom logger callback that scans all LLM calls at the
gateway/proxy level — protecting every model behind LiteLLM in one place.

Requires: litellm >= 1.0.0
    pip install litellm

Usage:
    import litellm
    from openclay import Shield
    from openclay.integrations.litellm import OpenClayLiteLLMCallback

    shield = Shield.balanced(
        sensitive_terms=["INTERNAL_API_KEY"],
        honeypot_tokens=["TRAP_SECRET_123"],
    )

    litellm.callbacks = [OpenClayLiteLLMCallback(shield=shield)]

    # All litellm.completion() calls are now protected
    response = litellm.completion(model="gpt-4", messages=[...])
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("openclay")

try:
    from litellm.integrations.custom_logger import CustomLogger

    _HAS_LITELLM = True
except ImportError:
    _HAS_LITELLM = False

    # Stub base class so the module can be imported for inspection
    class CustomLogger:
        pass


def _require_litellm():
    if not _HAS_LITELLM:
        raise ImportError(
            "LiteLLM integration requires litellm >= 1.0.0. "
            "Install with: pip install litellm"
        )


import contextvars

_threat_var: contextvars.ContextVar[float] = contextvars.ContextVar(
    "openclay_litellm_threat", default=0.0
)

class OpenClayLiteLLMCallback(CustomLogger):
    """
    LiteLLM custom logger that enforces OpenClay at the proxy level.

    Intercepts:
        log_pre_api_call    → protect_input() on messages before LLM
        log_success_event   → protect_output() on LLM response
        async_log_success_event → async protect_output()

    Blocked events are logged and optionally raise to prevent responses
    from reaching the caller.
    """

    def __init__(
        self,
        shield,
        system_context: str = "",
        raise_on_block: bool = True,
        on_block: Any = None,
    ):
        """
        Args:
            shield: Shield or AsyncShield instance
            system_context: System prompt for protect_input context
            raise_on_block: If True, raise on blocked input/output
            on_block: Optional callback(result_dict) on any block
        """
        _require_litellm()
        self.shield = shield
        self.system_context = system_context
        self.raise_on_block = raise_on_block
        self.on_block = on_block

        self.stats = {
            "inputs_scanned": 0,
            "inputs_blocked": 0,
            "outputs_scanned": 0,
            "outputs_blocked": 0,
        }

    def _handle_block(self, result: Dict, stage: str):
        """Handle a blocked event."""
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

    def _extract_text_from_messages(self, messages: List[Dict]) -> str:
        """Extract user-facing text from LiteLLM messages format."""
        texts = []
        for msg in messages:
            if isinstance(msg, dict):
                role = msg.get("role", "")
                content = msg.get("content", "")
                if role == "user" and isinstance(content, str):
                    texts.append(content)
            elif isinstance(msg, str):
                texts.append(msg)
        return " ".join(texts)

    # ── Pre-API Call (Input Protection) ──

    def log_pre_api_call(self, model, messages, kwargs):
        """Scan messages before the LLM API call is made."""
        try:
            if isinstance(messages, list):
                user_text = self._extract_text_from_messages(messages)
            else:
                user_text = str(messages)

            if not user_text.strip():
                return

            self.stats["inputs_scanned"] += 1
            result = self.shield.protect_input(user_text, self.system_context)
            _threat_var.set(result.get("threat_level", 0.0))

            if result.get("blocked"):
                self.stats["inputs_blocked"] += 1
                self._handle_block(result, "log_pre_api_call")

        except ValueError:
            raise  # Re-raise block exceptions
        except Exception as e:
            logger.warning("OpenClay log_pre_api_call failed: %s", e)

    # ── Success Event (Output Protection) ──

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Scan LLM response for data leaks (sync)."""
        self._scan_response(response_obj, "log_success_event")

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        """Scan LLM response for data leaks (async)."""
        import asyncio
        await asyncio.to_thread(
            self._scan_response, response_obj, "async_log_success_event"
        )

    def _scan_response(self, response_obj, stage: str):
        """Extract and scan response text."""
        try:
            # LiteLLM ModelResponse format
            text = ""
            if hasattr(response_obj, "choices"):
                for choice in response_obj.choices:
                    if hasattr(choice, "message") and hasattr(choice.message, "content"):
                        text += (choice.message.content or "")
                    elif hasattr(choice, "text"):
                        text += (choice.text or "")

            if not text.strip():
                return

            self.stats["outputs_scanned"] += 1
            result = self.shield.protect_output(
                model_output=text,
                input_threat_level=_threat_var.get(),
            )

            if result.get("blocked"):
                self.stats["outputs_blocked"] += 1
                self._handle_block(result, stage)

        except ValueError:
            raise  # Re-raise block exceptions
        except Exception as e:
            logger.warning("OpenClay %s scan failed: %s", stage, e)

    # ── Failure Event (Log only) ──

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        """Log LLM failures for observability (no blocking)."""
        logger.info("LiteLLM call failed — no OpenClay scan required")

    # ── Utility ──

    def get_stats(self) -> Dict:
        """Return scan statistics."""
        return self.stats.copy()
