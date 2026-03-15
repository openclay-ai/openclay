"""
Pattern Hot-Reload Manager

Thread-safe pattern manager with:
- Zero-downtime pattern updates
- Pattern versioning
- Effectiveness tracking
- A/B testing support
"""

import json
import logging
import os
import re
import threading
import time
import unicodedata
import base64
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("promptshield")


class PatternManager:
    """
    Thread-safe pattern manager with hot-reload capability.
    
    Features:
    - Hot-reload patterns without restart
    - Pattern version control
    - Track pattern effectiveness
    - A/B testing support
    - Thread-safe operations
    
    Usage:
        manager = PatternManager("promptshield/attack_db")
        matched, score, rule = manager.match(user_input)
        
        # Later, hot-reload new patterns
        manager.hot_reload()
    """
    
    def __init__(self, patterns_dir: str):
        """
        Initialize pattern manager.
        
        Args:
            patterns_dir: Directory containing pattern JSON files
        """
        self.patterns_dir = patterns_dir
        self.patterns = {}
        self.version = "1.0.0"
        self.last_reload = time.time()
        self.pattern_stats = {}  # Track hits per pattern
        self._lock = threading.RLock()  # Reentrant lock
        
        # Load initial patterns
        self.patterns = self._load_patterns()
    
    def _load_patterns(self) -> Dict:
        """Load all pattern files from directory"""
        patterns = {}
        
        if not os.path.exists(self.patterns_dir):
            logger.warning("Pattern directory not found: %s", self.patterns_dir)
            return patterns
        
        # Recursively find all JSON files
        for json_file in Path(self.patterns_dir).rglob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # Support both single pattern and array of patterns
                    if isinstance(data, list):
                        for pattern in data:
                            pattern_id = pattern.get('id', f"{json_file.stem}_{len(patterns)}")
                            patterns[pattern_id] = pattern
                    elif isinstance(data, dict):
                        # Check if it's a pattern collection
                        if 'patterns' in data:
                            for pattern in data['patterns']:
                                pattern_id = pattern.get('id', f"{json_file.stem}_{len(patterns)}")
                                patterns[pattern_id] = pattern
                        else:
                            # Single pattern
                            pattern_id = data.get('id', json_file.stem)
                            patterns[pattern_id] = data
                            
            except Exception as e:
                logger.warning("Failed to load %s: %s", json_file, e)
        
        logger.info("Loaded %d attack patterns", len(patterns))
        return patterns
    
    def _validate_patterns(self, patterns: Dict) -> bool:
        """
        Validate pattern structure.
        
        Required fields:
        - id: Unique identifier
        - pattern or regex: Match pattern
        - type: Attack type
        """
        required_fields = ['id']
        
        for pattern_id, pattern in patterns.items():
            # Check required fields
            for field in required_fields:
                if field not in pattern:
                    logger.warning("Pattern %s missing required field: %s", pattern_id, field)
                    return False
            
            # Check has at least one match method
            if not any(k in pattern for k in ['pattern', 'regex', 'keywords']):
                logger.warning("Pattern %s has no match criterion", pattern_id)
                return False
        
        return True
    
    def hot_reload(self) -> bool:
        """
        Reload patterns without restart (zero-downtime).
        
        Returns:
            True if reload successful, False otherwise
        """
        logger.info("Hot-reloading patterns...")
        
        try:
            # Load new patterns
            new_patterns = self._load_patterns()
            
            # Validate
            if not self._validate_patterns(new_patterns):
                logger.error("Pattern validation failed - keeping old patterns")
                return False
            
            # Atomic swap with write lock
            with self._lock:
                old_count = len(self.patterns)
                self.patterns = new_patterns
                self.version = self._increment_version()
                self.last_reload = time.time()
            
            new_count = len(new_patterns)
            logger.info("Patterns reloaded: %d → %d (version: %s)", old_count, new_count, self.version)
            
            return True
            
        except Exception as e:
            logger.error("Hot-reload failed: %s", e)
            return False
    
    @staticmethod
    def _decode_text(text: str) -> str:
        """
        Attempt to decode obfuscated text.
        Handles: URL encoding, Base64, Unicode homoglyphs, zero-width chars.
        Returns decoded version (or original if decoding adds nothing useful).
        """
        # 1. Unicode normalization (catches homoglyphs + zero-width spaces)
        normalized = unicodedata.normalize("NFKC", text)
        normalized = re.sub(r"[\u200B-\u200D\u2060\uFEFF\u00AD]", "", normalized)

        # 2. URL decode
        url_decoded = urllib.parse.unquote(normalized)

        # 3. Base64 decode attempt
        b64_decoded = url_decoded
        try:
            # Strip whitespace and attempt decode
            candidate = re.sub(r'\s+', '', url_decoded)
            padded = candidate + '=' * (-len(candidate) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
            candidate_text = decoded_bytes.decode('utf-8', errors='ignore')
            # Only accept if it looks like readable text (>5 chars, high ASCII ratio)
            printable_ratio = sum(c.isprintable() for c in candidate_text) / max(len(candidate_text), 1)
            if len(candidate_text) > 5 and printable_ratio > 0.8:
                b64_decoded = candidate_text
        except Exception:
            pass

        return b64_decoded

    def match(self, text: str) -> Tuple[bool, float, Optional[str]]:
        """
        Match text against all patterns.

        Runs matching on BOTH the raw text AND the decoded/normalized text
        to catch Base64, URL-encoded, and Unicode-obfuscated attacks.

        Args:
            text: Text to check

        Returns:
            Tuple of (matched, score, rule_id)
            - matched: True if any pattern matched
            - score: Highest match score (0.0-1.0)
            - rule_id: ID of matched rule (or None)
        """
        with self._lock:
            patterns_snapshot = self.patterns.copy()

        # Decode text to catch obfuscated attacks
        decoded_text = self._decode_text(text)
        # Combine: check raw + decoded surface (dedup via set)
        check_surfaces = [text]
        if decoded_text.strip().lower() != text.strip().lower():
            check_surfaces.append(decoded_text)

        best_match = None
        max_score = 0.0

        for pattern_id, pattern in patterns_snapshot.items():
            for surface in check_surfaces:
                score = self._check_pattern(surface, pattern)
                if score > max_score:
                    max_score = score
                    best_match = pattern_id
                if score > 0:
                    self._track_hit(pattern_id)

        matched = max_score > 0.6  # Threshold for blocking (raised from 0.5 to reduce FP)
        return matched, max_score, best_match
    
    def _check_pattern(self, text: str, pattern: Dict) -> float:
        """
        Check if text matches pattern.
        
        Returns match score (0.0-1.0)
        """
        import re
        
        text_lower = text.lower()
        score = 0.0
        
        # Check regex pattern
        if 'regex' in pattern:
            try:
                if re.search(pattern['regex'], text, re.IGNORECASE):
                    score = 0.9
            except re.error:
                pass
        
        # Check exact pattern
        if 'pattern' in pattern:
            if pattern['pattern'].lower() in text_lower:
                score = max(score, 0.8)
        
        # Check prompt field (for attack examples)
        if 'prompt' in pattern:
            prompt_lower = pattern['prompt'].lower()
            
            # 1. Exact phrase match (High confidence)
            if pattern['prompt'].lower() in text_lower:
                return 1.0
            
            # 2. Flexible overlap check (require input text is substantive)
            prompt_words = [w for w in prompt_lower.split() if len(w) > 2] # Ignore small words
            text_words = [w for w in text_lower.split() if len(w) > 2]
            
            if not prompt_words:
                return score

            # Skip fuzzy overlap for very short input (reduces FP on "What is X?" queries)
            if len(text_words) < 4:
                return score
                
            common = set(prompt_words) & set(text_words)
            overlap_count = len(common)
            
            # For short phrases (2-3 words), require FULL overlap (was n-1, too loose)
            if len(prompt_words) <= 3:
                if overlap_count >= len(prompt_words):
                    score = max(score, 0.85)
            # For longer phrases, use ratio
            else:
                ratio = overlap_count / len(prompt_words)
                if ratio > 0.6:  # >60% match
                    score = max(score, 0.9 * ratio)
                elif ratio > 0.4 and overlap_count >= 3: # >40% match with at least 3 words
                    score = max(score, 0.75 * ratio)
            
            # 3. Critical keyword boost
            critical_keywords = {'ignore', 'disregard', 'override', 'jailbreak', 'system', 'prompt', 'developer', 'mode'}
            critical_hits = common & critical_keywords
            if critical_hits and score > 0.0:
                score = min(score + 0.15, 1.0)
                
            # 4. Partial phrase matching (continuous sequence)
            # If 3+ consecutive words match, it's likely an attack
            if len(prompt_words) >= 4:
                for i in range(len(prompt_words) - 2):
                    phrase = " ".join(prompt_words[i:i+3])
                    if phrase in text_lower:
                        score = max(score, 0.8)
                        break
        
        # Check keywords
        if 'keywords' in pattern:
            keywords = pattern['keywords']
            if isinstance(keywords, str):
                keywords = [keywords]
            
            matches = sum(1 for kw in keywords if kw.lower() in text_lower)
            if matches > 0:
                keyword_score = min(0.7, matches / len(keywords))
                score = max(score, keyword_score)
        
        return score
    
    def _track_hit(self, pattern_id: str):
        """Track pattern hit for effectiveness metrics"""
        with self._lock:
            self.pattern_stats[pattern_id] = \
                self.pattern_stats.get(pattern_id, 0) + 1
    
    def _increment_version(self) -> str:
        """
        Increment semantic version.
        Format: MAJOR.MINOR.PATCH
        """
        parts = self.version.split('.')
        if len(parts) == 3:
            major, minor, patch = map(int, parts)
            patch += 1
            return f"{major}.{minor}.{patch}"
        else:
            # Fallback to timestamp-based
            now = datetime.now()
            return f"{now.year}.{now.month}{now.day}.{now.hour}{now.minute}"
    
    def get_stats(self) -> Dict:
        """
        Get pattern effectiveness statistics.
        
        Returns:
            Dictionary with:
            - total_patterns: Number of loaded patterns
            - total_hits: Total pattern matches
            - top_patterns: Most effective patterns
            - version: Current pattern version
        """
        with self._lock:
            stats_snapshot = self.pattern_stats.copy()
        
        # Sort by hit count
        sorted_patterns = sorted(
            stats_snapshot.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            "total_patterns": len(self.patterns),
            "total_hits": sum(stats_snapshot.values()),
            "top_patterns": sorted_patterns[:10],
            "version": self.version,
            "last_reload": datetime.fromtimestamp(self.last_reload).isoformat()
        }
    
    def get_pattern(self, pattern_id: str) -> Optional[Dict]:
        """Get specific pattern by ID"""
        with self._lock:
            return self.patterns.get(pattern_id)
    
    def list_patterns(self) -> List[str]:
        """List all pattern IDs"""
        with self._lock:
            return list(self.patterns.keys())


# Auto-reload daemon (optional)
class PatternAutoReloader:
    """
    Daemon that automatically hot-reloads patterns on file changes.
    
    Usage:
        reloader = PatternAutoReloader(pattern_manager, check_interval=60)
        reloader.start()
        
        # Later
        reloader.stop()
    """
    
    def __init__(self, pattern_manager: PatternManager, check_interval: int = 60):
        """
        Initialize auto-reloader.
        
        Args:
            pattern_manager: PatternManager instance
            check_interval: Seconds between checks
        """
        self.pattern_manager = pattern_manager
        self.check_interval = check_interval
        self._running = False
        self._thread = None
        self._last_mtime = self._get_directory_mtime()
    
    def _get_directory_mtime(self) -> float:
        """Get latest modification time of pattern directory"""
        try:
            mtimes = []
            for json_file in Path(self.pattern_manager.patterns_dir).rglob("*.json"):
                mtimes.append(os.path.getmtime(json_file))
            return max(mtimes) if mtimes else 0
        except:
            return 0
    
    def _reload_loop(self):
        """Background loop that checks for changes"""
        while self._running:
            time.sleep(self.check_interval)
            
            current_mtime = self._get_directory_mtime()
            if current_mtime > self._last_mtime:
                logger.info("Pattern files changed, triggering hot-reload...")
                if self.pattern_manager.hot_reload():
                    self._last_mtime = current_mtime
    
    def start(self):
        """Start auto-reload daemon"""
        if self._running:
            logger.warning("Auto-reloader already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._reload_loop, daemon=True)
        self._thread.start()
        logger.info("Pattern auto-reloader started (interval: %ds)", self.check_interval)
    
    def stop(self):
        """Stop auto-reload daemon"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Pattern auto-reloader stopped")
