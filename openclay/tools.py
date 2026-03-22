"""
OpenClay Tool Security  (v0.2.0)

Decorators that wrap *any* tool function with automatic input/output
shield scanning — so poisoned tool outputs never reach the agent context.

Usage::

    from openclay import ClayTool, Shield

    @ClayTool(shield=Shield.strict())
    def search_web(query: str) -> str:
        return requests.get(f"https://api.example.com?q={query}").text

    result = search_web("quantum computing")  # scanned automatically
"""

from __future__ import annotations

import warnings
from functools import wraps
from typing import Any, Callable, Optional

from .tracing import Trace


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class ToolOutputBlocked(Exception):
    """
    Raised when a tool's input or output is rejected by the shield.

    Attributes
    ----------
    trace : Trace
        Explainability trace for the block decision.
    """

    def __init__(self, message: str, trace: Optional[Trace] = None):
        super().__init__(message)
        self.trace = trace


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------

def ClayTool(shield=None, scan_input: bool = True, scan_output: bool = True):
    """
    Decorator factory that wraps a tool function with shield scanning.

    Parameters
    ----------
    shield : Shield, optional
        A ``Shield`` instance.  Defaults to ``Shield.fast()`` if omitted.
    scan_input : bool
        Scan the stringified arguments before execution (default ``True``).
    scan_output : bool
        Scan the return value before handing it back to the caller
        (default ``True``).

    Examples
    --------
    ::

        @ClayTool(shield=Shield.balanced())
        def read_file(path: str) -> str:
            return open(path).read()

        # The return value is scanned. If poisoned, raises ToolOutputBlocked.
        content = read_file("/tmp/data.txt")
    """

    def decorator(func: Callable) -> Callable:
        # Resolve shield lazily so module-level decoration works even if
        # Shield hasn't been imported by the caller yet.
        _shield = shield

        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            nonlocal _shield

            # Lazy-init shield on first call
            if _shield is None:
                from .shields import Shield
                _shield = Shield.fast()

            # ── 1. Scan input ────────────────────────────────────
            input_text = _build_input_text(args, kwargs)

            if scan_input:
                input_result = _shield.protect_input(
                    user_input=input_text,
                    system_context="",      # tools have no system prompt
                )
                if input_result.get("blocked"):
                    trace = Trace(
                        blocked=True,
                        layer="tool_input",
                        reason=input_result.get("reason"),
                        rule=input_result.get("rule"),
                        threat_level=input_result.get("threat_level", 0.0),
                        threat_breakdown=input_result.get("threat_breakdown", {}),
                    )
                    wrapper.last_trace = trace
                    raise ToolOutputBlocked(
                        f"Tool input blocked: {input_result.get('reason')}",
                        trace=trace,
                    )

            # ── 2. Execute ───────────────────────────────────────
            result = func(*args, **kwargs)

            # ── 3. Scan output ───────────────────────────────────
            if scan_output:
                output_result = _shield.protect_output(
                    model_output=str(result),
                    user_input=input_text,
                )
                if output_result.get("blocked"):
                    trace = Trace(
                        blocked=True,
                        layer="tool_output",
                        reason=output_result.get("reason"),
                        rule=output_result.get("rule"),
                        threat_level=output_result.get("threat_level", 0.0),
                        threat_breakdown=output_result.get("threat_breakdown", {}),
                    )
                    wrapper.last_trace = trace
                    raise ToolOutputBlocked(
                        f"Tool output blocked: {output_result.get('reason')}",
                        trace=trace,
                    )

                # Use the (possibly sanitised) output from the shield
                result = output_result.get("output", result)

            # ── 4. Clean result ──────────────────────────────────
            wrapper.last_trace = Trace(
                blocked=False,
                layer="tool",
                threat_level=0.0,
            )
            return result

        # Attach metadata to the wrapper
        wrapper.shield = shield
        wrapper.last_trace = None
        wrapper._is_clay_tool = True
        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_input_text(args: tuple, kwargs: dict) -> str:
    """Flatten tool args/kwargs into a single scannable string."""
    parts = [str(a) for a in args]
    parts.extend(f"{k}={v}" for k, v in kwargs.items())
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Deprecated alias
# ---------------------------------------------------------------------------

def tool(shield=None):
    """Deprecated — use :func:`ClayTool` instead."""
    warnings.warn(
        "openclay.tools.tool() is deprecated. Use ClayTool() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return ClayTool(shield=shield)
