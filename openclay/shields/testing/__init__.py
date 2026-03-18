"""
OpenClay Testing Module

Automated adversarial testing and evasion detection.
"""

from .evasion_tester import OpenClayEvasionTester, run_evasion_tests

__all__ = [
    "OpenClayEvasionTester",
    "run_evasion_tests",
]
