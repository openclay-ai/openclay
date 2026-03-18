"""
PII Redaction

Smart redaction modes for PII found in LLM outputs.

Modes:
- MASK: Replace with [REDACTED]
- HASH: Replace with hash (deterministic)
- PARTIAL: Show partial (j***@***.com)
- REMOVE: Remove entirely
"""

import hashlib
from enum import Enum
from typing import List

from .contextual_detector import PIIFinding, PIIType


class RedactionMode(Enum):
    """PII redaction modes"""
    MASK = "mask"          # [REDACTED]
    HASH = "hash"          # a7f3k9x2
    PARTIAL = "partial"    # j***@***.com
    REMOVE = "remove"      # ""


def redact_pii(
    text: str,
    findings: List[PIIFinding],
    mode: RedactionMode = RedactionMode.MASK
) -> str:
    """
    Redact PII from text.
    
    Args:
        text: Original text
        findings: PIIFinding objects from detector
        mode: Redaction mode
    
    Returns:
        Redacted text
    """
    if not findings:
        return text
    
    # Sort findings by position (reverse to maintain indices)
    sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)
    
    redacted = text
    
    for finding in sorted_findings:
        original = finding.value
        replacement = _get_replacement(finding, mode)
        
        # Replace in text
        redacted = (
            redacted[:finding.start] +
            replacement +
            redacted[finding.end:]
        )
    
    return redacted


def _get_replacement(finding: PIIFinding, mode: RedactionMode) -> str:
    """Get replacement string for PII based on mode"""
    
    if mode == RedactionMode.MASK:
        return f"[{finding.pii_type.value.upper()}_REDACTED]"
    
    elif mode == RedactionMode.HASH:
        # Deterministic hash (same PII → same hash)
        hash_obj = hashlib.sha256(finding.value.encode())
        return hash_obj.hexdigest()[:8]
    
    elif mode == RedactionMode.PARTIAL:
        return _partial_redact(finding)
    
    elif mode == RedactionMode.REMOVE:
        return ""
    
    else:
        return "[REDACTED]"


def _partial_redact(finding: PIIFinding) -> str:
    """
    Partially redact PII (show first/last chars).
    
    Examples:
    - Email: j***@***.com
    - Phone: +1 (***) ***-1234
    - Credit card: **** **** **** 1234
    """
    value = finding.value
    pii_type = finding.pii_type
    
    if pii_type == PIIType.EMAIL:
        # john@example.com → j***@***.com
        if '@' in value:
            local, domain = value.split('@', 1)
            if '.' in domain:
                domain_parts = domain.rsplit('.', 1)
                return f"{local[0]}***@***.{domain_parts[1]}"
        return "***@***.***"
    
    elif pii_type == PIIType.PHONE:
        # Show last 4 digits
        digits = ''.join(c for c in value if c.isdigit())
        if len(digits) >= 4:
            return f"***-***-{digits[-4:]}"
        return "***-***-****"
    
    elif pii_type == PIIType.CREDIT_CARD:
        # Show last 4 digits
        digits = ''.join(c for c in value if c.isdigit())
        if len(digits) >= 4:
            return f"**** **** **** {digits[-4:]}"
        return "**** **** **** ****"
    
    elif pii_type == PIIType.SSN:
        # Show last 4
        digits = ''.join(c for c in value if c.isdigit())
        if len(digits) >= 4:
            return f"***-**-{digits[-4:]}"
        return "***-**-****"
    
    elif pii_type == PIIType.API_KEY:
        # Show first 6 chars
        if len(value) >= 10:
            return f"{value[:6]}...{value[-4:]}"
        return "***"
    
    else:
        # Generic: show first char
        if len(value) > 1:
            return f"{value[0]}***"
        return "***"


def smart_redact(
    text: str,
    findings: List[PIIFinding]
) -> str:
    """
    Smart redaction based on PII severity.
    
    - CRITICAL (credentials) → MASK
    - WARNING (third-party) → PARTIAL
    - INFO (user's own) → No redaction
    """
    if not findings:
        return text
    
    # Separate by severity
    critical = [f for f in findings if f.severity.value == "critical"]
    warnings = [f for f in findings if f.severity.value == "warning"]
    
    # Redact critical with MASK
    redacted = redact_pii(text, critical, RedactionMode.MASK)
    
    # Redact warnings with PARTIAL
    redacted = redact_pii(redacted, warnings, RedactionMode.PARTIAL)
    
    # INFO findings are not redacted
    
    return redacted


# Example usage
if __name__ == "__main__":
    from .contextual_detector import PIIFinding, PIIType, PIISeverity
    
    text = "Contact john@example.com or call +1-555-123-4567. API key: sk-1234567890abcdefghijk"
    
    # Mock findings
    findings = [
        PIIFinding(
            pii_type=PIIType.EMAIL,
            value="john@example.com",
            start=8,
            end=25,
            severity=PIISeverity.WARNING
        ),
        PIIFinding(
            pii_type=PIIType.PHONE,
            value="+1-555-123-4567",
            start=34,
            end=49,
            severity=PIISeverity.WARNING
        ),
        PIIFinding(
            pii_type=PIIType.API_KEY,
            value="sk-1234567890abcdefghijk",
            start=60,
            end=83,
            severity=PIISeverity.CRITICAL
        )
    ]
    
    print("Original:")
    print(f"  {text}")
    print()
    
    print("MASK mode:")
    print(f"  {redact_pii(text, findings, RedactionMode.MASK)}")
    print()
    
    print("PARTIAL mode:")
    print(f"  {redact_pii(text, findings, RedactionMode.PARTIAL)}")
    print()
    
    print("HASH mode:")
    print(f"  {redact_pii(text, findings, RedactionMode.HASH)}")
    print()
    
    print("Smart redact (severity-based):")
    print(f"  {smart_redact(text, findings)}")
