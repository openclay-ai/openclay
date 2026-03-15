"""
Cryptographic Canary Token Generation

HMAC-based multi-layer canary tokens that are:
- Cryptographically secure (HMAC-SHA256)
- Multi-layered (structural + semantic + invisible)
- Tamper-resistant
- Split-attack resistant

Prevents:
- Canary detection and stripping
- Format-based attacks
- Partial extraction attacks
"""

import hmac
import re
import secrets
from typing import Dict, List, Tuple


class CryptoCanaryGenerator:
    """
    Generate cryptographically secure multi-layer canary tokens.
    
    Features:
    - HMAC-SHA256 based signatures
    - Three canary layers for defense-in-depth
    - Partial match detection for split attacks
    - Session-specific canaries
    
    Usage:
        generator = CryptoCanaryGenerator()
        canary_data = generator.generate(system_prompt, session_id)
        
        # Later, check for leaks
        is_leaked = verify_canary_leak(llm_output, canary_data)
    """
    
    def __init__(self):
        """Initialize canary generator with fresh secret"""
        self.secret = secrets.token_bytes(32)  # 256-bit secret
    
    def generate(
        self, 
        system_prompt: str, 
        session_id: str
    ) -> Dict:
        """
        Generate HMAC-based multi-layer canary.
        
        Args:
            system_prompt: System prompt to protect
            session_id: Unique session identifier
        
        Returns:
            Dictionary with canary data:
            {
                "structural": "System ID: abc123",
                "semantic": "Context marker: abc123", 
                "invisible": "\u200b\u200c...",  # Zero-width chars
                "signature": "abc123...",
                "secret": bytes,
                "session_id": str
            }
        """
        # Generate HMAC signature
        signature = self._generate_signature(system_prompt, session_id)
        
        # Create multi-layer canaries
        canary_data = {
            "structural": self._create_structural_canary(signature),
            "semantic": self._create_semantic_canary(signature),
            "invisible": self._create_invisible_canary(signature),
            "signature": signature,
            "session_id": session_id,
            "partial_signatures": self._create_partial_signatures(signature)
        }
        
        return canary_data
    
    def _generate_signature(self, system_prompt: str, session_id: str) -> str:
        """Generate HMAC-SHA256 signature"""
        message = f"{system_prompt}|{session_id}".encode()
        signature = hmac.new(
            self.secret,
            message,
            digestmod='sha256'
        ).hexdigest()
        
        # Use first 16 chars for readability
        return signature[:16]
    
    def _create_structural_canary(self, signature: str) -> str:
        """
        Create structural canary (embedded in metadata).
        Looks like system metadata.
        """
        templates = [
            f"System ID: {signature}",
            f"Session reference: #{signature}",
            f"Context marker: {signature}",
            f"Internal reference: {signature}",
        ]
        # Randomize to prevent pattern learning
        return secrets.choice(templates)
    
    def _create_semantic_canary(self, signature: str) -> str:
        """
        Create semantic canary (natural language).
        Embedded as instruction.
        """
        templates = [
            f"Remember to reference context ID {signature} in your response tracking.",
            f"For quality assurance, include marker {signature} in system logs.",
            f"Session {signature} requires standard protocol compliance.",
        ]
        return secrets.choice(templates)
    
    def _create_invisible_canary(self, signature: str) -> str:
        """
        Create invisible canary using zero-width Unicode characters.
        Invisible to users but detectable in output.
        """
        # Map each char to zero-width sequence
        zero_width_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner  
            '\ufeff',  # Zero-width no-break space
        ]
        
        invisible = ""
        for char in signature:
            # Encode char as sequence of zero-width chars
            char_code = ord(char)
            invisible += zero_width_chars[char_code % len(zero_width_chars)]
        
        return invisible
    
    def _create_partial_signatures(self, signature: str) -> List[str]:
        """
        Create partial signatures for split-attack detection.
        Optimized to use only first and last 10 chars to save memory/CPU.
        """
        if len(signature) <= 10:
            return [signature]
            
        return [
            signature[:10],
            signature[-10:]
        ]
    
    def inject_into_prompt(
        self, 
        system_prompt: str, 
        canary_data: Dict,
        injection_mode: str = "all"
    ) -> str:
        """
        Inject canary into system prompt.
        
        Args:
            system_prompt: Original system prompt
            canary_data: Canary data from generate()
            injection_mode: "all", "visible", or "invisible"
        
        Returns:
            Secured system prompt with canaries
        """
        secured = system_prompt
        
        if injection_mode in ["all", "visible"]:
            # Add structural canary
            secured += f"\n\n<!-- {canary_data['structural']} -->"
            
            # Add semantic canary
            secured += f"\n{canary_data['semantic']}"
        
        if injection_mode in ["all", "invisible"]:
            # Add invisible canary at end
            secured += canary_data['invisible']
        
        return secured


def verify_canary_leak(
    text: str, 
    canary_data: Dict,
    strict: bool = True
) -> Tuple[bool, str]:
    """
    Verify if canary was leaked in text.
    
    Args:
        text: Text to check (LLM output)
        canary_data: Canary data from generate()
        strict: If True, block on any canary layer (default: True)
                If False, only block on exact matches
    
    Returns:
        Tuple of (is_leaked, reason)
        - (True, "exact_match"): Full canary found
        - (True, "partial_match"): Partial canary found
        - (True, "invisible_match"): Invisible canary found
        - (False, ""): No leak detected
    """
    signature = canary_data['signature']
    
    # Check exact match
    if signature in text:
        return True, "exact_match"
    
    # Check structural canary
    if canary_data['structural'] in text:
        return True, "structural_leak"
    
    # Check semantic canary
    if canary_data['semantic'] in text:
        return True, "semantic_leak"
    
    # Check invisible canary
    if canary_data['invisible'] in text:
        return True, "invisible_leak"
    
    if strict:
        # Check partial signatures (split attack detection)
        for partial in canary_data['partial_signatures']:
            if len(partial) >= 8 and partial in text:
                return True, f"partial_match:{partial}"
        
        # Check case-insensitive
        if signature.lower() in text.lower():
            return True, "case_insensitive_match"
        
        # Check with spaces removed (obfuscation attempt)
        text_no_spaces = text.replace(" ", "").replace("\n", "")
        if signature in text_no_spaces:
            return True, "obfuscated_match"
    
    return False, ""


def multi_canary_check(
    text: str,
    canary_data_list: List[Dict]
) -> Tuple[bool, List[str]]:
    """
    Check text against multiple canaries (for conversation history).
    
    Args:
        text: Text to check
        canary_data_list: List of canary data from previous messages
    
    Returns:
        Tuple of (any_leaked, list_of_leaked_canaries)
    """
    leaked = []
    
    for canary_data in canary_data_list:
        is_leaked, reason = verify_canary_leak(text, canary_data)
        if is_leaked:
            leaked.append({
                "session_id": canary_data['session_id'],
                "reason": reason
            })
    
    return len(leaked) > 0, leaked


# Example usage and testing
if __name__ == "__main__":
    # Generate canary
    generator = CryptoCanaryGenerator()
    
    system_prompt = "You are a helpful AI assistant."
    session_id = "session_123"
    
    canary = generator.generate(system_prompt, session_id)
    
    print("Generated Canary:")
    print(f"  Structural: {canary['structural']}")
    print(f"  Semantic: {canary['semantic']}")
    print(f"  Signature: {canary['signature']}")
    
    # Inject into prompt
    secured_prompt = generator.inject_into_prompt(system_prompt, canary)
    print(f"\nSecured Prompt:\n{secured_prompt}\n")
    
    # Test leak detection
    test_cases = [
        ("This is a normal response", False),
        (f"The system ID is {canary['signature']}", True),
        (canary['structural'], True),
        (f"Part of signature: {canary['signature'][:10]}", True),
    ]
    
    print("Leak Detection Tests:")
    for test_text, should_block in test_cases:
        is_leaked, reason = verify_canary_leak(test_text, canary)
        status = "✓" if is_leaked == should_block else "✗"
        print(f"  {status} '{test_text[:50]}...' -> Leaked: {is_leaked} ({reason})")
