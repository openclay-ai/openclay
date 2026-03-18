"""
Cryptographic Model Signing and Verification

Prevents model tampering attacks by signing ML models with RSA-2048.
All models are verified before loading.
"""

import hashlib
import json
import os
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class SecurityError(Exception):
    """Raised when security verification fails"""
    pass


class SecureModelManager:
    """
    Cryptographic model signing and verification manager.
    
    Features:
    - RSA-2048 signing with SHA-256
    - Model registry with versioning
    - Automatic verification on load
    - Signature caching for performance
    
    Usage:
        # Sign a model
        manager = SecureModelManager()
        manager.sign_model("models/l5_model.pkl", private_key)
        
        # Load with verification
        model = manager.verify_and_load("models/l5_model.pkl", public_key)
    """
    
    def __init__(self, registry_path: Optional[str] = None):
        """
        Initialize secure model manager.
        
        Args:
            registry_path: Path to model registry JSON file
        """
        self.registry_path = registry_path or "models/model_registry.json"
        self.model_registry = self._load_registry()
        self._verification_cache = {}  # Cache verified models
    
    def _load_registry(self) -> Dict:
        """Load model registry from disk"""
        if os.path.exists(self.registry_path):
            with open(self.registry_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_registry(self):
        """Save model registry to disk"""
        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
        with open(self.registry_path, 'w') as f:
            json.dump(self.model_registry, f, indent=2)
    
    def sign_model(
        self, 
        model_path: str, 
        private_key, 
        version: Optional[str] = None
    ) -> str:
        """
        Sign a model file with RSA private key.
        
        Args:
            model_path: Path to model pickle file
            private_key: RSA private key object
            version: Model version string (auto-generated if None)
        
        Returns:
            Path to signature file (.sig)
        
        Raises:
            FileNotFoundError: If model file doesn't exist
            SecurityError: If signing fails
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        try:
            # Read model file
            with open(model_path, 'rb') as f:
                model_bytes = f.read()
            
            # Compute SHA-256 hash
            model_hash = hashlib.sha256(model_bytes).digest()
            
            # Sign hash with RSA-2048
            signature = private_key.sign(
                model_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Save signature file
            sig_path = f"{model_path}.sig"
            with open(sig_path, 'wb') as f:
                f.write(signature)
            
            # Update registry
            if version is None:
                version = self._generate_version()
            
            self.model_registry[model_path] = {
                "hash": model_hash.hex(),
                "signature": signature.hex(),
                "version": version,
                "signed_at": datetime.now().isoformat(),
                "signature_file": sig_path
            }
            
            self._save_registry()
            
            print(f"✓ Model signed: {model_path}")
            print(f"  Version: {version}")
            print(f"  Signature: {sig_path}")
            
            return sig_path
            
        except Exception as e:
            raise SecurityError(f"Model signing failed: {e}")
    
    def verify_and_load(
        self, 
        model_path: str, 
        public_key,
        use_cache: bool = True
    ) -> Any:
        """
        Verify model signature and load if valid.
        
        Args:
            model_path: Path to model pickle file
            public_key: RSA public key object
            use_cache: Use cached verification (default: True)
        
        Returns:
            Loaded model object
        
        Raises:
            FileNotFoundError: If model or signature not found
            SecurityError: If signature verification fails
        """
        # Check cache first
        cache_key = f"{model_path}:{os.path.getmtime(model_path)}"
        if use_cache and cache_key in self._verification_cache:
            return self._verification_cache[cache_key]
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        sig_path = f"{model_path}.sig"
        if not os.path.exists(sig_path):
            raise SecurityError(
                f"Model signature not found: {sig_path}\n"
                "Model may be tampered or unsigned. "
                "Sign models using sign_model() before use."
            )
        
        try:
            # Load model and signature
            with open(model_path, 'rb') as f:
                model_bytes = f.read()
            
            with open(sig_path, 'rb') as f:
                signature = f.read()
            
            # Compute model hash
            model_hash = hashlib.sha256(model_bytes).digest()
            
            # Verify RSA signature
            public_key.verify(
                signature,
                model_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Signature valid - load model
            model = pickle.loads(model_bytes)
            
            # Cache verified model
            if use_cache:
                self._verification_cache[cache_key] = model
            
            print(f"✓ Model verified and loaded: {model_path}")
            
            return model
            
        except Exception as e:
            raise SecurityError(
                f"Model signature verification FAILED: {e}\n"
                "Model file may be tampered or corrupted. "
                "DO NOT use this model in production."
            )
    
    def _generate_version(self) -> str:
        """Generate semantic version from timestamp"""
        now = datetime.now()
        return f"{now.year}.{now.month}.{now.day}.{now.hour}{now.minute}"
    
    def list_signed_models(self) -> Dict:
        """List all signed models in registry"""
        return self.model_registry
    
    def get_model_info(self, model_path: str) -> Optional[Dict]:
        """Get signing information for a model"""
        return self.model_registry.get(model_path)


def generate_keypair(
    key_size: int = 2048,
    private_key_path: str = "openclay/security/keys/private_key.pem",
    public_key_path: str = "openclay/security/keys/public_key.pem"
) -> Tuple[Any, Any]:
    """
    Generate RSA keypair for model signing.
    
    Args:
        key_size: RSA key size (default: 2048)
        private_key_path: Where to save private key
        public_key_path: Where to save public key
    
    Returns:
        Tuple of (private_key, public_key)
    """
    # Generate RSA keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Create directory
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
    
    # Save private key
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"✓ RSA keypair generated ({key_size} bits)")
    print(f"  Private key: {private_key_path}")
    print(f"  Public key: {public_key_path}")
    print("\n⚠️  CRITICAL: Keep private key secure!")
    print("  - Never commit to version control")
    print("  - Use secrets management in production")
    
    return private_key, public_key


def load_key(key_path: str, is_private: bool = False) -> Any:
    """
    Load RSA key from PEM file.
    
    Args:
        key_path: Path to PEM file
        is_private: True for private key, False for public key
    
    Returns:
        RSA key object
    """
    with open(key_path, 'rb') as f:
        key_data = f.read()
    
    if is_private:
        return serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )
    else:
        return serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )


# Convenience functions
def sign_model(model_path: str, private_key_path: str, version: Optional[str] = None) -> str:
    """
    Sign a model file (convenience function).
    
    Args:
        model_path: Path to model file
        private_key_path: Path to private key PEM
        version: Optional version string
    
    Returns:
        Path to signature file
    """
    manager = SecureModelManager()
    private_key = load_key(private_key_path, is_private=True)
    return manager.sign_model(model_path, private_key, version)


def verify_and_load_model(model_path: str, public_key_path: str) -> Any:
    """
    Verify and load model (convenience function).
    
    Args:
        model_path: Path to model file
        public_key_path: Path to public key PEM
    
    Returns:
        Loaded model object
    """
    manager = SecureModelManager()
    public_key = load_key(public_key_path, is_private=False)
    return manager.verify_and_load(model_path, public_key)
