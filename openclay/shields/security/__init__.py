"""
OpenClay Security Module

Cryptographic security components for model signing, canary generation,
and integrity verification.
"""

from .model_signing import SecureModelManager, sign_model, verify_and_load_model
from .canary_crypto import CryptoCanaryGenerator, verify_canary_leak

__all__ = [
    "SecureModelManager",
    "sign_model",
    "verify_and_load_model",
    "CryptoCanaryGenerator",
    "verify_canary_leak",
]
