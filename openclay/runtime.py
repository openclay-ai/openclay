"""
OpenClay Secure Runtime Engine  (v0.4.0)


The execution wrapper that enforces shields before and after *any* callable.
Think of it as a firewall for function calls — nothing executes without
passing through a trust boundary first.

Usage::

    from openclay import ClayRuntime

    runtime = ClayRuntime(policy="strict")
    result  = runtime.run(my_llm_call, user_input, context=system_prompt)

    if result.blocked:
        print(result.trace.explain())
    else:
        print(result.output)
"""

from __future__ import annotations

import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union

from .policies import Policy, StrictPolicy, ModeratePolicy, AuditPolicy, CustomPolicy
from .tracing import Trace

# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class ClayResult:
    """
    Immutable result of a ``ClayRuntime.run()`` call.

    Attributes
    ----------
    output : Any
        The return value of the callable (``None`` when blocked).
    blocked : bool
        ``True`` if a shield stopped execution or rejected the output.
    trace : Trace
        Full explainability trace for the call.
    """
    output: Any = None
    blocked: bool = False
    trace: Optional[Trace] = None


# ---------------------------------------------------------------------------
# Core Runtime
# ---------------------------------------------------------------------------

class ClayRuntime:
    """
    Secure execution runtime.

    Wraps *any* callable so that:

    1. Input is scanned through ``Shield.protect_input``
    2. The callable executes
    3. Output is scanned through ``Shield.protect_output``
    4. A full ``Trace`` is recorded

    Parameters
    ----------
    policy : str | Policy
        ``"strict"`` / ``"balanced"`` / ``"fast"`` / ``"secure"``
        or a ``Policy`` instance.
    shield : Shield, optional
        Provide your own ``Shield``.  If omitted one is created from
        the *policy* string.
    trace : bool
        Store explainability traces (default ``True``).
    """

    # Mapping from policy string → Shield factory preset
    _SHIELD_PRESETS = {
        "strict":   "strict",
        "balanced": "balanced",
        "fast":     "fast",
        "secure":   "secure",
    }

    def __init__(
        self,
        policy: Union[str, Policy] = "balanced",
        shield=None,                       # Shield instance (optional)
        trace: bool = True,
    ):
        # Resolve policy object
        if isinstance(policy, str):
            self._policy_name = policy
            self.policy = {
                "strict":   StrictPolicy,
                "balanced": ModeratePolicy,
                "fast":     ModeratePolicy,    # fast uses same policy, lighter shield
                "secure":   StrictPolicy,
            }.get(policy, ModeratePolicy)()
        else:
            self._policy_name = "custom"
            self.policy = policy

        # Resolve shield
        if shield is not None:
            self.shield = shield
        else:
            self.shield = self._make_shield(self._policy_name)

        self._trace_enabled = trace
        self._last_trace: Optional[Trace] = None
        self._disabled_layers: set = set(self.policy.disabled_layers) if isinstance(self.policy, Policy) else set()

    # ------------------------------------------------------------------
    # Shield factory (lazy import to avoid circular deps at module level)
    # ------------------------------------------------------------------

    @staticmethod
    def _make_shield(preset: str):
        """Create a Shield from a named preset string."""
        from .shields import Shield
        factory = getattr(Shield, preset, None)
        if factory is None:
            return Shield.balanced()
        return factory()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(
        self,
        fn: Callable,
        input_data: Any,
        *,
        context: str = "",
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ClayResult:
        """
        Execute *fn(input_data)* inside a secure boundary.

        Parameters
        ----------
        fn : callable
            Any function / LLM call / chain.  Called as ``fn(input_data)``.
        input_data : Any
            The data handed to *fn*.  Will be cast to ``str`` for shield scanning.
        context : str
            System prompt or context string (passed to ``protect_input``).
        user_id, session_id : str, optional
            Forwarded to the shield for rate limiting / session tracking.

        Returns
        -------
        ClayResult
        """
        t0 = time.perf_counter()
        text_input = str(input_data)

        # ── 1. Input shield ──────────────────────────────────────────
        input_result: Dict = {}
        if "input" not in self._disabled_layers:
            input_result = self.shield.protect_input(
                user_input=text_input,
                system_context=context,
                user_id=user_id,
                session_id=session_id,
            )
            if input_result.get("blocked") and getattr(self.policy, 'auto_block', True):
                trace = self._build_trace(
                    blocked=True,
                    layer="input",
                    input_result=input_result,
                    t0=t0,
                )
                return ClayResult(output=None, blocked=True, trace=trace)

        # ── 2. Execute ───────────────────────────────────────────────
        output = fn(input_data)

        # ── 3. Output shield ─────────────────────────────────────────
        output_result: Dict = {}
        if "output" not in self._disabled_layers:
            canary = input_result.get("canary")
            output_result = self.shield.protect_output(
                model_output=str(output),
                canary=canary,
                user_id=user_id,
                user_input=text_input,
            )
            if output_result.get("blocked") and getattr(self.policy, 'auto_block', True):
                trace = self._build_trace(
                    blocked=True,
                    layer="output",
                    input_result=input_result,
                    output_result=output_result,
                    t0=t0,
                )
                return ClayResult(output=None, blocked=True, trace=trace)

            # Use the (possibly redacted) output from the shield
            output = output_result.get("output", output)

        # ── 4. Safe result ───────────────────────────────────────────
        trace = self._build_trace(
            blocked=False,
            layer=None,
            input_result=input_result,
            output_result=output_result,
            t0=t0,
        )
        return ClayResult(output=output, blocked=False, trace=trace)

    # ------------------------------------------------------------------
    # Trace builder
    # ------------------------------------------------------------------

    def _build_trace(
        self,
        blocked: bool,
        layer: Optional[str],
        input_result: Dict = None,
        output_result: Dict = None,
        t0: float = 0.0,
    ) -> Optional[Trace]:
        if not self._trace_enabled:
            return None

        # Determine the dominant result (whichever blocked, or output)
        active = (input_result or {}) if layer == "input" else (output_result or {})

        trace = Trace(
            blocked=blocked,
            layer=layer,
            reason=active.get("reason"),
            rule=active.get("rule"),
            threat_level=active.get("threat_level", 0.0),
            threat_breakdown=active.get("threat_breakdown", {}),
            latency_ms=(time.perf_counter() - t0) * 1000 if t0 else 0.0,
            input_result=input_result if input_result else None,
            output_result=output_result if output_result else None,
            recommendation=self._recommend(blocked, active),
            policy_name=getattr(self.policy, 'name', self._policy_name),
        )
        self._last_trace = trace
        return trace

    @staticmethod
    def _recommend(blocked: bool, result: Dict) -> str:
        if not blocked:
            return "Input and output passed all shield checks."
        reason = result.get("reason", "unknown")
        return f"Blocked by {reason}. Review the trace for details."

    # ------------------------------------------------------------------
    # Trace access
    # ------------------------------------------------------------------

    def last_trace(self) -> Optional[Trace]:
        """Return the :class:`Trace` from the most recent ``run()`` call."""
        return self._last_trace

    # Legacy compat — old stub used `.trace()`
    def trace(self) -> Optional[Trace]:     # noqa: D401
        return self._last_trace

    # ------------------------------------------------------------------
    # Wrap external agents (LangChain / CrewAI / any .run()-able)
    # ------------------------------------------------------------------

    def wrap(self, agent: Any) -> "WrappedAgent":
        """
        Return a proxy that routes ``agent.run()`` / ``agent.invoke()``
        through the runtime's shield pipeline.

        Works with any object that exposes ``.run(input)`` or
        ``.invoke(input)`` — LangChain chains, CrewAI crews, etc.
        """
        return WrappedAgent(agent, self)

    # ------------------------------------------------------------------
    # Explicit unsafe context managers
    # ------------------------------------------------------------------

    @contextmanager
    def disable(self, *layers: str):
        """
        Temporarily disable specific shield layers.

        Usage::

            with runtime.disable("output"):
                result = runtime.run(fn, data)

        Valid layer names: ``"input"``, ``"output"``, ``"semantic"``.
        """
        added = set(layers)
        self._disabled_layers |= added
        try:
            yield
        finally:
            self._disabled_layers -= added

    @contextmanager
    def trust(self, *layers: str):
        """Alias for :meth:`disable` — semantically means *trust this layer*."""
        with self.disable(*layers):
            yield


# ---------------------------------------------------------------------------
# Wrapped external agent
# ---------------------------------------------------------------------------

class WrappedAgent:
    """
    Transparent proxy that routes an external agent's execution through
    :class:`ClayRuntime`.

    Supports any object with ``.run(input)`` or ``.invoke(input)``.
    """

    def __init__(self, agent: Any, runtime: ClayRuntime):
        self._agent = agent
        self._runtime = runtime

    def run(self, input_data: Any, **kwargs) -> ClayResult:
        return self._runtime.run(self._agent.run, input_data, **kwargs)

    def invoke(self, input_data: Any, **kwargs) -> ClayResult:
        fn = getattr(self._agent, "invoke", self._agent.run)
        return self._runtime.run(fn, input_data, **kwargs)

    def __getattr__(self, name: str):
        """Proxy everything else to the wrapped agent."""
        return getattr(self._agent, name)


# ---------------------------------------------------------------------------
# Deprecated alias
# ---------------------------------------------------------------------------

class SecureRuntime(ClayRuntime):
    """Deprecated — use :class:`ClayRuntime` instead."""

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "SecureRuntime is deprecated. Use ClayRuntime instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
