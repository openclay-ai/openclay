# __init__.py
"""
PromptShield: Universal AI Security Framework

New Configurable Shield API (v2.0):
    from promptshield import Shield
    
    # Use presets
    shield = Shield.fast()       # Pattern-only
    shield = Shield.balanced()   # Production default
    shield = Shield.secure()     # Full protection
    
    # Or customize
    shield = Shield(
        patterns=True,
        canary=True,
        rate_limiting=True,
        pii_detection=True
    )

Legacy API (Deprecated):
    from promptshield.shields import InputShield_L5  # Deprecated
"""

__version__ = "2.7.0"

# New configurable Shield (recommended)
from .shields import Shield, register_component, ShieldComponent
from .shields_async import AsyncShield
from .exceptions import StreamBlockedError, PromptShieldError

__all__ = [
    "Shield",
    "AsyncShield",
    "register_component",
    "ShieldComponent",
    "StreamBlockedError",
    "PromptShieldError",
]

# Legacy shields (deprecated but supported)
from .shields import InputShield_L5, OutputShield_L5, AgentShield_L3

# Core utilities
from .methods import (
    sanitize_text,
    pattern_match,
    complexity_score,
    generate_canary,
    inject_canary,
    detect_canary,
    pii_scan,
    load_attack_patterns,
)

# Security components
from .security import (
    SecureModelManager,
    sign_model,
    verify_and_load_model,
    CryptoCanaryGenerator,
    verify_canary_leak,
)

# Advanced components
from .pattern_manager import PatternManager
from .rate_limiting import AdaptiveRateLimiter
from .session_anomaly import SessionAnomalyDetector

# PII detection
from .pii import (
    ContextualPIIDetector,
    PIIContext,
    RedactionMode,
    redact_pii,
    smart_redact,
)

# Training validation
from .training import DatasetValidator

# Testing
from .testing import PromptShieldEvasionTester

__all__ = [
    # Main Shield API (v2.0)
    "Shield",
    "AsyncShield",
    "register_component",
    "ShieldComponent",
    
    # Legacy shields (deprecated)
    "InputShield_L5",
    "OutputShield_L5",
    "AgentShield_L3",
    
    # Utilities
    "sanitize_text",
    "pattern_match",
    "complexity_score",
    "generate_canary",
    "inject_canary",
    "detect_canary",
    "pii_scan",
    "load_attack_patterns",
    
    # Security
    "SecureModelManager",
    "sign_model",
    "verify_and_load_model",
    "CryptoCanaryGenerator",
    "verify_canary_leak",
    
    # Components
    "PatternManager",
    "AdaptiveRateLimiter",
    "SessionAnomalyDetector",
    "ContextualPIIDetector",
    "PIIContext",
    "RedactionMode",
    "redact_pii",
    "smart_redact",
    "DatasetValidator",
    "PromptShieldEvasionTester",
]
