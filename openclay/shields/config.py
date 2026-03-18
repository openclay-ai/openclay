"""
OpenClay Configuration System

Load shield configuration from YAML files for centralized, code-free policy management.

Usage:
    shield = Shield.from_config("openclay.yml")
    
Example YAML:
    preset: balanced
    webhook_url: https://hooks.slack.com/...
    allowlist_file: safe_phrases.txt
    custom_patterns:
      - "DROP TABLE"
      - "rm -rf"
"""

import os
import json
from typing import Dict, Any, Optional, List


def load_yaml(path: str) -> Dict[str, Any]:
    """
    Load YAML config file. Falls back to JSON if PyYAML is not installed.
    
    Args:
        path: Path to the config file (.yml, .yaml, or .json)
        
    Returns:
        Dictionary of configuration values
        
    Raises:
        FileNotFoundError: If the config file doesn't exist
        ValueError: If the file format is unsupported or parsing fails
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    
    ext = os.path.splitext(path)[1].lower()
    
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    
    if ext in (".yml", ".yaml"):
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            raise ImportError(
                "PyYAML is required for YAML config files. "
                "Install it with: pip install pyyaml"
            )
    
    raise ValueError(f"Unsupported config file format: {ext}. Use .yml, .yaml, or .json")


def load_allowlist_file(path: str) -> List[str]:
    """
    Load allowlist phrases from a text file (one phrase per line).
    
    Args:
        path: Path to the allowlist file
        
    Returns:
        List of safe phrases (lowercased, stripped)
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Allowlist file not found: {path}")
    
    phrases = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  # Skip empty lines and comments
                phrases.append(line.lower())
    
    return phrases


def resolve_config(raw_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Resolve a raw YAML/JSON config into Shield constructor kwargs.
    
    Supports:
        - preset: str (fast/balanced/strict/secure/paranoid)
        - All Shield.__init__ parameters
        - allowlist_file: str (path to allowlist text file)
        - webhook_url: str (URL for detection alerts)
        
    Args:
        raw_config: Raw dictionary from config file
        
    Returns:
        Dictionary of kwargs suitable for Shield() or Shield.preset()
    """
    config = dict(raw_config)  # Don't mutate original
    
    # Handle allowlist_file → merge into allowlist
    if "allowlist_file" in config:
        file_phrases = load_allowlist_file(config.pop("allowlist_file"))
        existing = config.get("allowlist", [])
        if isinstance(existing, list):
            config["allowlist"] = existing + file_phrases
        else:
            config["allowlist"] = file_phrases
    
    # Handle custom_patterns_file → merge into custom_patterns
    if "custom_patterns_file" in config:
        pattern_path = config.pop("custom_patterns_file")
        if not os.path.exists(pattern_path):
            raise FileNotFoundError(f"Custom patterns file not found: {pattern_path}")
        with open(pattern_path, "r", encoding="utf-8") as f:
            file_patterns = [
                line.strip() for line in f 
                if line.strip() and not line.startswith("#")
            ]
        existing = config.get("custom_patterns", [])
        if isinstance(existing, list):
            config["custom_patterns"] = existing + file_patterns
        else:
            config["custom_patterns"] = file_patterns
    
    return config
