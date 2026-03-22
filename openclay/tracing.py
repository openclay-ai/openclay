"""
OpenClay Tracing and Explainability Engine.

Provides structured traces that explain exactly why an action was
blocked or allowed, which layer caught it, and the associated threat scores.
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass, field, asdict
import time


@dataclass
class Trace:
    """
    Immutable record of a single shield pass (input or output).

    Every ``ClayRuntime.run()`` and ``@ClayTool`` invocation produces a
    Trace that can be inspected, logged, or forwarded to an observability
    backend.
    """

    # Was the action ultimately blocked?
    blocked: bool = False

    # Which layer made the decision
    layer: Optional[str] = None          # "input" | "output" | "tool_input" | "tool_output"

    # Human-readable reason (mirrors Shield result keys)
    reason: Optional[str] = None         # "pattern_match" | "ml_detection" | "canary_leak" | …

    # Specific rule that triggered (if pattern-based)
    rule: Optional[str] = None

    # Aggregate threat score 0.0 – 1.0
    threat_level: float = 0.0

    # Per-layer breakdown
    threat_breakdown: Dict[str, float] = field(default_factory=dict)

    # Wall-clock time for the shield pass (ms)
    latency_ms: float = 0.0

    # Raw shield result dicts (kept for power users)
    input_result: Optional[Dict] = None
    output_result: Optional[Dict] = None

    # Recommendation string for operators
    recommendation: Optional[str] = None

    # ──────────────────────────────────────────────
    # Public helpers
    # ──────────────────────────────────────────────

    def explain(self) -> str:
        """One-line human-readable verdict."""
        status = "BLOCKED" if self.blocked else "ALLOWED"
        parts = [f"[{status}]"]
        if self.layer:
            parts.append(f"Layer: {self.layer}")
        if self.reason:
            parts.append(f"Reason: {self.reason}")
        parts.append(f"Threat: {self.threat_level:.2f}")
        if self.latency_ms:
            parts.append(f"Latency: {self.latency_ms:.1f}ms")
        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable dictionary (safe for logging / tracing systems)."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    # Legacy compat
    def summary(self) -> str:          # noqa: D401
        return self.explain()

    def __repr__(self) -> str:
        return f"Trace({self.explain()})"
