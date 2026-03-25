"""
OpenClay Policy Engine  (v0.4.0)

Policies define the security posture for a ClayRuntime, Knight, or Squad.
They control which shield layers are active, threat thresholds, and
explicit allow/deny rules — making every trust decision visible in code.

Usage::

    from openclay import StrictPolicy, CustomPolicy

    # Pre-built policy
    runtime = ClayRuntime(policy=StrictPolicy())

    # Custom policy with fine-grained control
    policy = CustomPolicy(
        max_threat_level=0.3,
        disabled_layers=["rate_limiter"],
        allow_pii=False,
        trust_tools=False,
    )
    knight = Knight(name="scout", llm_caller=fn, policy=policy)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Base Policy
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    """
    Base policy defining execution rules and risk tolerances.

    Attributes
    ----------
    name : str
        Human-readable policy identifier.
    allow_pii : bool
        If ``True``, PII in outputs is allowed through without redaction.
    trust_tools : bool
        If ``True``, tool outputs skip shield scanning.
    max_threat_level : float
        Aggregate threat score threshold (0.0–1.0). Anything above is blocked.
    disabled_layers : set
        Shield layers explicitly disabled (e.g. ``{"rate_limiter", "ml_ensemble"}``).
    shield_preset : str
        The Shield factory preset to use (``"fast"`` / ``"balanced"`` /
        ``"strict"`` / ``"secure"``).
    scan_memory_writes : bool
        If ``True``, memory writes are scanned before persisting.
    scan_memory_reads : bool
        If ``True``, memory reads are scanned before entering agent context.
    auto_block : bool
        If ``True``, threats above *max_threat_level* raise immediately.
        If ``False``, the trace is populated but execution is allowed (audit mode).
    """

    name: str = "base"
    allow_pii: bool = False
    trust_tools: bool = False
    max_threat_level: float = 0.5
    disabled_layers: Set[str] = field(default_factory=set)
    shield_preset: str = "balanced"
    scan_memory_writes: bool = True
    scan_memory_reads: bool = True
    auto_block: bool = True

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def should_scan(self, layer: str) -> bool:
        """Return ``True`` if the given layer should be active."""
        return layer not in self.disabled_layers

    def is_threat(self, threat_level: float) -> bool:
        """Return ``True`` if *threat_level* exceeds the policy threshold."""
        return threat_level > self.max_threat_level

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable snapshot of the policy configuration."""
        return {
            "name": self.name,
            "allow_pii": self.allow_pii,
            "trust_tools": self.trust_tools,
            "max_threat_level": self.max_threat_level,
            "disabled_layers": sorted(self.disabled_layers),
            "shield_preset": self.shield_preset,
            "scan_memory_writes": self.scan_memory_writes,
            "scan_memory_reads": self.scan_memory_reads,
            "auto_block": self.auto_block,
        }

    def __repr__(self) -> str:
        return f"Policy(name={self.name!r}, threat≤{self.max_threat_level}, preset={self.shield_preset!r})"


# ---------------------------------------------------------------------------
# Built-in presets
# ---------------------------------------------------------------------------

class StrictPolicy(Policy):
    """
    Zero-trust policy.  Maximum shields, lowest threat threshold.

    * All layers active
    * Threat threshold: **0.1**
    * Shield preset: ``strict``
    * No PII allowed, tools untrusted
    """

    def __init__(self):
        super().__init__(
            name="strict",
            allow_pii=False,
            trust_tools=False,
            max_threat_level=0.1,
            disabled_layers=set(),
            shield_preset="strict",
            scan_memory_writes=True,
            scan_memory_reads=True,
            auto_block=True,
        )


class ModeratePolicy(Policy):
    """
    Production default.  Balanced security and flexibility.

    * All layers active
    * Threat threshold: **0.5**
    * Shield preset: ``balanced``
    """

    def __init__(self):
        super().__init__(
            name="moderate",
            allow_pii=False,
            trust_tools=False,
            max_threat_level=0.5,
            disabled_layers=set(),
            shield_preset="balanced",
            scan_memory_writes=True,
            scan_memory_reads=True,
            auto_block=True,
        )


class AuditPolicy(Policy):
    """
    Observe-only mode.  Scans everything but never blocks.

    Useful for shadow-deploying OpenClay alongside existing systems
    to measure what *would* have been blocked without interrupting
    production traffic.

    * All layers active (for tracing)
    * ``auto_block`` is ``False``
    """

    def __init__(self):
        super().__init__(
            name="audit",
            allow_pii=False,
            trust_tools=False,
            max_threat_level=0.5,
            disabled_layers=set(),
            shield_preset="balanced",
            scan_memory_writes=True,
            scan_memory_reads=True,
            auto_block=False,         # ← key difference
        )


class CustomPolicy(Policy):
    """
    Fully developer-controlled policy.

    Pass any combination of parameters to fine-tune the security posture::

        policy = CustomPolicy(
            max_threat_level=0.3,
            disabled_layers={"rate_limiter", "session_anomaly"},
            trust_tools=True,
            shield_preset="fast",
        )
    """

    def __init__(
        self,
        max_threat_level: float = 0.5,
        disabled_layers: Optional[Set[str]] = None,
        allow_pii: bool = False,
        trust_tools: bool = False,
        shield_preset: str = "balanced",
        scan_memory_writes: bool = True,
        scan_memory_reads: bool = True,
        auto_block: bool = True,
    ):
        super().__init__(
            name="custom",
            allow_pii=allow_pii,
            trust_tools=trust_tools,
            max_threat_level=max_threat_level,
            disabled_layers=disabled_layers or set(),
            shield_preset=shield_preset,
            scan_memory_writes=scan_memory_writes,
            scan_memory_reads=scan_memory_reads,
            auto_block=auto_block,
        )
