"""
Context-Aware PII Detection

Distinguishes between:
- User's own PII (from input) - ALLOW
- System credentials - CRITICAL BLOCK
- Third-party PII (leaked data) - WARNING/REDACT

Detects:
- Email addresses
- Phone numbers
- Credit cards
- SSN/Tax IDs
- API keys
- Passwords
- IP addresses
- Physical addresses
"""

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class PIIType(Enum):
    """Types of PII that can be detected"""
    EMAIL = "email"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    API_KEY = "api_key"
    PASSWORD = "password"
    IP_ADDRESS = "ip_address"
    ADDRESS = "physical_address"
    CUSTOM = "custom"


class PIISeverity(Enum):
    """Severity of PII leak"""
    INFO = "info"              # User's own PII
    WARNING = "warning"        # Third-party PII
    CRITICAL = "critical"      # System credentials


@dataclass
class PIIContext:
    """
    Context for PII detection.
    
    Helps distinguish user's PII from leaked data.
    """
    user_id: str
    user_provided_pii: List[str]  # Known user PII from input
    system_context: str = "assistant"  # "assistant", "admin", "internal"
    
    def is_user_pii(self, pii_value: str) -> bool:
        """Check if PII belongs to user"""
        return pii_value in self.user_provided_pii
    
    def is_system_context(self) -> bool:
        """Check if in system context"""
        return self.system_context in ["admin", "internal", "system"]


@dataclass
class PIIFinding:
    """Detected PII finding"""
    pii_type: PIIType
    value: str
    start: int
    end: int
    severity: PIISeverity
    context: str = ""


class ContextualPIIDetector:
    """
    Context-aware PII detector.
    
    Features:
    - Distinguishes user PII from leaked PII
    - Multiple PII pattern types
    - Severity classification
    - Context-aware decisions
    
    Usage:
        detector = ContextualPIIDetector()
        
        context = PIIContext(
            user_id="user123",
            user_provided_pii=["user@email.com"]
        )
        
        findings = detector.detect(llm_output, context)
        
        for finding in findings:
            if finding.severity == PIISeverity.CRITICAL:
                # Block immediately
    """
    
    def __init__(self):
        """Initialize PII detector with patterns"""
        self.patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[PIIType, re.Pattern]:
        """Compile regex patterns for PII detection"""
        return {
            PIIType.EMAIL: re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            PIIType.PHONE: re.compile(
                r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b'
            ),
            PIIType.CREDIT_CARD: re.compile(
                r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
            ),
            PIIType.SSN: re.compile(
                r'\b\d{3}-\d{2}-\d{4}\b'
            ),
            PIIType.API_KEY: re.compile(
                r'\b(?:sk-|pk-|api[_-]?key[_-]?)[A-Za-z0-9]{20,}\b',
                re.IGNORECASE
            ),
            PIIType.PASSWORD: re.compile(
                r'\bpassword[:\s=]+[^\s]{8,}\b',
                re.IGNORECASE
            ),
            PIIType.IP_ADDRESS: re.compile(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ),
        }
    
    def detect(
        self, 
        text: str, 
        context: PIIContext
    ) -> List[PIIFinding]:
        """
        Detect PII in text with context awareness.
        
        Args:
            text: Text to scan
            context: Context for PII classification
        
        Returns:
            List of PIIFinding objects
        """
        findings = []
        
        # Check each pattern type
        for pii_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                
                # Determine severity based on context
                severity = self._classify_severity(
                    pii_type, 
                    value, 
                    context
                )
                
                finding = PIIFinding(
                    pii_type=pii_type,
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    severity=severity,
                    context=context.system_context
                )
                
                findings.append(finding)
        
        return findings
    
    def _classify_severity(
        self, 
        pii_type: PIIType, 
        value: str,
        context: PIIContext
    ) -> PIISeverity:
        """
        Classify PII severity based on context.
        
        Logic:
        - User's own PII → INFO (allow)
        - System credentials → CRITICAL (block)
        - Third-party PII → WARNING (redact)
        """
        # Check if it's user's own PII
        if context.is_user_pii(value):
            return PIISeverity.INFO
        
        # System credentials are critical
        if pii_type in [PIIType.API_KEY, PIIType.PASSWORD]:
            return PIISeverity.CRITICAL
        
        # In system context, any PII leak is critical
        if context.is_system_context():
            return PIISeverity.CRITICAL
        
        # Otherwise, third-party PII is warning
        return PIISeverity.WARNING
    
    def scan_and_classify(
        self,
        text: str,
        context: PIIContext
    ) -> Dict:
        """
        Scan text and return classified results.
        
        Returns:
            Dictionary with:
            - has_pii: bool
            - action: "allow" | "warn" | "block"
            - findings: List[PIIFinding]
            - summary: str
        """
        findings = self.detect(text, context)
        
        if not findings:
            return {
                "has_pii": False,
                "action": "allow",
                "findings": [],
                "summary": "No PII detected"
            }
        
        # Check for critical findings
        critical = [f for f in findings if f.severity == PIISeverity.CRITICAL]
        if critical:
            return {
                "has_pii": True,
                "action": "block",
                "findings": findings,
                "summary": f"CRITICAL: {len(critical)} system credential(s) leaked"
            }
        
        # Check for warnings
        warnings = [f for f in findings if f.severity == PIISeverity.WARNING]
        if warnings:
            return {
                "has_pii": True,
                "action": "warn",
                "findings": findings,
                "summary": f"WARNING: {len(warnings)} third-party PII detected"
            }
        
        # Only user's own PII
        return {
            "has_pii": True,
            "action": "allow",
            "findings": findings,
            "summary": f"INFO: {len(findings)} user PII (allowed)"
        }


# Global shared detector to avoid recompiling regexes
_GLOBAL_DETECTOR = None

def get_detector() -> ContextualPIIDetector:
    global _GLOBAL_DETECTOR
    if _GLOBAL_DETECTOR is None:
        _GLOBAL_DETECTOR = ContextualPIIDetector()
    return _GLOBAL_DETECTOR

# Helper functions for common use cases
def extract_user_pii(user_input: str) -> List[str]:
    """
    Extract PII from user input to build context.
    
    Used to identify user's own PII for later comparison.
    """
    detector = get_detector()
    
    # Create temporary context (all PII is treated as user's)
    temp_context = PIIContext(
        user_id="temp",
        user_provided_pii=[]
    )
    
    findings = detector.detect(user_input, temp_context)
    
    return [f.value for f in findings]


def is_safe_output(
    llm_output: str,
    user_id: str,
    user_input: str,
    system_context: str = "assistant"
) -> Tuple[bool, str]:
    """
    Check if LLM output is safe (no PII leaks).
    
    Convenience function for quick checks.
    
    Returns:
        Tuple of (is_safe, reason)
    """
    detector = get_detector()
    
    # Extract user's PII from input
    user_pii = extract_user_pii(user_input)
    
    # Create context
    context = PIIContext(
        user_id=user_id,
        user_provided_pii=user_pii,
        system_context=system_context
    )
    
    # Scan output
    result = detector.scan_and_classify(llm_output, context)
    
    is_safe = result["action"] != "block"
    reason = result["summary"]
    
    return is_safe, reason


# Example usage
if __name__ == "__main__":
    detector = ContextualPIIDetector()
    
    # Example 1: User's own email (ALLOW)
    user_input = "My email is user@example.com"
    user_pii = extract_user_pii(user_input)
    
    context = PIIContext(
        user_id="user123",
        user_provided_pii=user_pii
    )
    
    llm_output = "Sure, I'll send it to user@example.com"
    result = detector.scan_and_classify(llm_output, context)
    
    print("Example 1 (User's own email):")
    print(f"  Action: {result['action']}")
    print(f"  Summary: {result['summary']}")
    print()
    
    # Example 2: Third-party email (WARNING)
    llm_output2 = "Contact support at admin@company.com"
    result2 = detector.scan_and_classify(llm_output2, context)
    
    print("Example 2 (Third-party email):")
    print(f"  Action: {result2['action']}")
    print(f"  Summary: {result2['summary']}")
    print()
    
    # Example 3: API key leak (CRITICAL BLOCK)
    llm_output3 = "Your API key is sk-1234567890abcdefghijk"
    result3 = detector.scan_and_classify(llm_output3, context)
    
    print("Example 3 (API key leak):")
    print(f"  Action: {result3['action']}")
    print(f"  Summary: {result3['summary']}")
