"""
OpenClay Tracing & Telemetry Engine  (v0.4.0)

Provides structured, deterministic traces that explain exactly *why*
an action was blocked or allowed, which layer caught it, the associated
threat scores, and the policy configuration that was active.

Every ``ClayRuntime.run()``, ``@ClayTool``, and ``Knight.run()`` call
produces a ``Trace``.  Multiple traces can be collected into a
``TraceLog`` for end-to-end observability of multi-step workflows.

Usage::

    result = runtime.run(fn, input_data)
    print(result.trace.explain())       # one-liner
    print(result.trace.to_json())       # deterministic JSON telemetry
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict


# ---------------------------------------------------------------------------
# Core Trace
# ---------------------------------------------------------------------------

@dataclass
class Trace:
    """
    Immutable record of a single shield pass (input or output).

    Every ``ClayRuntime.run()`` and ``@ClayTool`` invocation produces a
    Trace that can be inspected, logged, or forwarded to an observability
    backend.
    """

    # Unique identifier for this trace event
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    # ISO-8601 timestamp
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    # Was the action ultimately blocked?
    blocked: bool = False

    # Which layer made the decision
    layer: Optional[str] = None          # "input" | "output" | "tool_input" | "tool_output" | "memory_write" | "memory_read"

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

    # Policy name that was active during this trace
    policy_name: Optional[str] = None

    # Entity that produced the trace (e.g. Knight name)
    source: Optional[str] = None

    # ──────────────────────────────────────────────
    # Public helpers
    # ──────────────────────────────────────────────

    def explain(self) -> str:
        """One-line human-readable verdict."""
        status = "🛡️ BLOCKED" if self.blocked else "✅ ALLOWED"
        parts = [f"[{status}]"]
        if self.source:
            parts.append(f"Source: {self.source}")
        if self.layer:
            parts.append(f"Layer: {self.layer}")
        if self.reason:
            parts.append(f"Reason: {self.reason}")
        parts.append(f"Threat: {self.threat_level:.2f}")
        if self.policy_name:
            parts.append(f"Policy: {self.policy_name}")
        if self.latency_ms:
            parts.append(f"Latency: {self.latency_ms:.1f}ms")
        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable dictionary (safe for logging / tracing systems)."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    def to_json(self, indent: int = 2) -> str:
        """Deterministic JSON telemetry string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)

    # Legacy compat
    def summary(self) -> str:          # noqa: D401
        return self.explain()

    def __repr__(self) -> str:
        return f"Trace({self.explain()})"


# ---------------------------------------------------------------------------
# TraceLog — collect multiple traces for multi-step workflows
# ---------------------------------------------------------------------------

@dataclass
class TraceLog:
    """
    Ordered collection of :class:`Trace` events from a multi-step execution
    (e.g. a Knight run, a Squad deployment, or a multi-tool chain).

    Provides aggregate statistics and full JSON export for observability
    pipelines.
    """

    events: List[Trace] = field(default_factory=list)

    def append(self, trace: Trace) -> None:
        """Add a trace event to the log."""
        if trace is not None:
            self.events.append(trace)

    @property
    def blocked_count(self) -> int:
        """Number of events that were blocked."""
        return sum(1 for e in self.events if e.blocked)

    @property
    def total_count(self) -> int:
        return len(self.events)

    @property
    def total_latency_ms(self) -> float:
        return sum(e.latency_ms for e in self.events)

    @property
    def max_threat_level(self) -> float:
        """Highest threat score across all events."""
        if not self.events:
            return 0.0
        return max(e.threat_level for e in self.events)

    @property
    def has_blocks(self) -> bool:
        return self.blocked_count > 0

    def explain(self) -> str:
        """Multi-line summary of all trace events."""
        if not self.events:
            return "[TraceLog] No events recorded."
        lines = [f"[TraceLog] {self.total_count} events | {self.blocked_count} blocked | {self.total_latency_ms:.1f}ms total"]
        for i, e in enumerate(self.events, 1):
            lines.append(f"  {i}. {e.explain()}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Full JSON-serialisable log."""
        return {
            "total_events": self.total_count,
            "blocked_count": self.blocked_count,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "max_threat_level": round(self.max_threat_level, 4),
            "events": [e.to_dict() for e in self.events],
        }

    def to_json(self, indent: int = 2) -> str:
        """Full deterministic JSON telemetry export."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)

    def __repr__(self) -> str:
        return f"TraceLog(events={self.total_count}, blocked={self.blocked_count})"
