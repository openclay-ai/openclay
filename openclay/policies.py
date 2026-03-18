"""
OpenClay Policy Engine.
Defines the strictness and behavior of the SecureRuntime.
"""

from typing import Dict, Any

class Policy:
    """Base defining execution rules and allowed risk tolerances."""
    def __init__(self, allow_pii: bool = False, trust_tools: bool = False, max_threat_level: float = 0.5):
        self.allow_pii = allow_pii
        self.trust_tools = trust_tools
        self.max_threat_level = max_threat_level

class StrictPolicy(Policy):
    """Zero-trust policy. Throws exceptions on any detected threat."""
    def __init__(self):
        super().__init__(allow_pii=False, trust_tools=False, max_threat_level=0.1)

class ModeratePolicy(Policy):
    """Production default. Balances flexibility and security."""
    def __init__(self):
        super().__init__(allow_pii=False, trust_tools=False, max_threat_level=0.5)

class CustomPolicy(Policy):
    """Developer-controlled policy."""
    pass
