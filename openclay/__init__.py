"""
OpenClay - The Secure Agentic Framework
"""

__version__ = "0.1.0"

from .shields import Shield, AsyncShield
from .runtime import SecureRuntime
from .agents import Agent
from .tools import tool
from .memory import SecureMemory
from .policies import Policy, StrictPolicy, ModeratePolicy, CustomPolicy
from .tracing import Trace

__all__ = [
    "Shield",
    "AsyncShield",
    "SecureRuntime",
    "Agent",
    "tool",
    "SecureMemory",
    "Policy",
    "StrictPolicy",
    "ModeratePolicy",
    "CustomPolicy",
    "Trace",
]
