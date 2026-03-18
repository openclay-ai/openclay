"""
OpenClay Tracing and Explainability Engine.
"""

from typing import Optional, Dict, Any

class Trace:
    """Explains why an action was blocked or permitted by the shield."""
    
    def __init__(self, action: str, allowed: bool, reason: str, threat_score: float, layer: str):
        self.action = action
        self.allowed = allowed
        self.reason = reason
        self.threat_score = threat_score
        self.layer = layer
        
    def summary(self) -> str:
        status = "ALLOWED" if self.allowed else "BLOCKED"
        return f"[{status}] Action: {self.action} | Layer: {self.layer} | Score: {self.threat_score} | Reason: {self.reason}"
