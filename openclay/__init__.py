"""
OpenClay - The Secure Agentic Framework

Every boundary is a trust decision.
OpenClay makes those decisions explicit.
"""

__version__ = "1.0.0"

# ── Core Shield API ──────────────────────────────────────────────────
from .shields import Shield, AsyncShield

# ── Runtime (v0.2.0) ────────────────────────────────────────────────
from .runtime import ClayRuntime, ClayResult, SecureRuntime, WrappedAgent

# ── Tools (v0.2.0) ──────────────────────────────────────────────────
from .tools import ClayTool, ToolOutputBlocked, tool

# ── Tracing (v0.4.0) ────────────────────────────────────────────────
from .tracing import Trace, TraceLog

# ── Policies (v0.4.0) ───────────────────────────────────────────────
from .policies import Policy, StrictPolicy, ModeratePolicy, AuditPolicy, CustomPolicy

# ── Knights (v0.3.0) ────────────────────────────────────────────────
from .knights import Knight, Squad

# ── Memory (v0.3.0) ─────────────────────────────────────────────────
from .memory import ClayMemory, MemoryWriteBlocked, MemoryReadBlocked

# ── Golem (v1.0.0) ──────────────────────────────────────────────────
from .golem import Golem, GolemResult

__all__ = [
    # Shield
    "Shield",
    "AsyncShield",

    # Runtime (v0.2.0)
    "ClayRuntime",
    "ClayResult",
    "SecureRuntime",
    "WrappedAgent",

    # Tools (v0.2.0)
    "ClayTool",
    "ToolOutputBlocked",
    "tool",

    # Tracing (v0.4.0)
    "Trace",
    "TraceLog",

    # Policies (v0.4.0)
    "Policy",
    "StrictPolicy",
    "ModeratePolicy",
    "AuditPolicy",
    "CustomPolicy",

    # Knights (v0.3.0)
    "Knight",
    "Squad",

    # Memory (v0.3.0)
    "ClayMemory",
    "MemoryWriteBlocked",
    "MemoryReadBlocked",

    # Golem (v1.0.0)
    "Golem",
    "GolemResult",
]
