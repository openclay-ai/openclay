"""
Output Engine — Multi-layer, high-performance output scanning pipeline.

Architecture (layers execute sequentially, short-circuit on first match):
    Layer 1: Bloom Filter Pre-Gate     → microsecond "definitely not" filter
    Layer 2: Aho-Corasick Scanner      → O(n) exact string matching
    Layer 3: Honeypot Trap             → fake secret leak detection
    Layer 4: Embedding Similarity      → semantic DLP (BYO-VDB or local)

Usage:
    from promptshield.output_engine import OutputEngine

    engine = OutputEngine(
        sensitive_terms=["API_KEY=sk-abc123", "internal.corp.net"],
        honeypot_tokens=["HONEYPOT_SECRET_XYZ"],
    )

    result = engine.scan(output_text)
    # → {"blocked": True, "reason": "aho_corasick_match", "matched_term": "..."}
"""

import logging
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("promptshield")


class OutputEngine:
    """
    Multi-layer output scanning engine for Data Loss Prevention.

    Layers are ordered by speed (fastest first) so clean outputs
    exit in microseconds without touching expensive ML models.
    """

    def __init__(
        self,
        sensitive_terms: Optional[List[str]] = None,
        honeypot_tokens: Optional[List[str]] = None,
        embedding_threshold: float = 0.78,
        output_filter=None,
    ):
        """
        Initialize the output engine.

        Args:
            sensitive_terms: List of exact strings to detect (API keys, URLs, secrets)
            honeypot_tokens: Fake secrets injected as canary traps
            embedding_threshold: Cosine similarity threshold for semantic matching
            output_filter: OutputFilter instance for BM25-based DLP matching
        """
        self.embedding_threshold = embedding_threshold
        self.honeypot_tokens = honeypot_tokens or []
        self._honeypot_log: List[Dict] = []

        # Layer 0: BM25 OutputFilter (user-defined sensitive data)
        self._output_filter = output_filter

        # Layer 1: Build Bloom Filter (includes BOTH sensitive terms AND honeypots)
        self._bloom = None
        all_bloom_terms = (sensitive_terms or []) + (honeypot_tokens or [])
        if all_bloom_terms:
            self._build_bloom_filter(all_bloom_terms)

        # Layer 2: Build Aho-Corasick Automaton
        self._automaton = None
        if sensitive_terms:
            self._build_aho_corasick(sensitive_terms)

        # Layer 3: Honeypot set (fast O(1) lookups)
        self._honeypot_set = set(t.lower() for t in self.honeypot_tokens)

        logger.info(
            "OutputEngine initialized: output_filter=%s, bloom=%s, aho_corasick=%s, honeypots=%d",
            self._output_filter is not None,
            self._bloom is not None,
            self._automaton is not None,
            len(self._honeypot_set),
        )

    # ─────────────────────────────────────────────
    # Layer 1: Bloom Filter Pre-Gate
    # ─────────────────────────────────────────────

    def _build_bloom_filter(self, terms: List[str]) -> None:
        """Build a Bloom Filter from sensitive terms using character shingles."""
        try:
            from pybloom_live import BloomFilter

            # Use character-level shingles for compound terms (API keys, URLs, etc.)
            shingle_size = 8
            # Estimate capacity: each term generates multiple shingles
            estimated_shingles = sum(max(1, len(t) - shingle_size + 1) for t in terms) + len(terms)
            self._bloom = BloomFilter(capacity=max(estimated_shingles, 100), error_rate=0.001)
            self._bloom_shingle_size = shingle_size

            for term in terms:
                term_lower = term.lower()
                # Add the full term
                self._bloom.add(term_lower)
                # Add character-level shingles for substring matching
                if len(term_lower) >= shingle_size:
                    for i in range(len(term_lower) - shingle_size + 1):
                        self._bloom.add(term_lower[i : i + shingle_size])
                else:
                    # Short terms: add as-is
                    self._bloom.add(term_lower)

            logger.info("Bloom filter built with %d terms (%d shingles)", len(terms), estimated_shingles)
        except ImportError:
            logger.warning(
                "pybloom_live not installed. Bloom filter disabled. "
                "Install with: pip install pybloom_live"
            )
            self._bloom_shingle_size = 8

    def _bloom_check(self, text: str) -> bool:
        """
        Fast pre-gate check. Returns True if text MIGHT contain a sensitive term.
        Returns False if it DEFINITELY does not (guaranteed by Bloom Filter math).
        """
        if self._bloom is None:
            return True  # No bloom filter → pass through to next layer

        text_lower = text.lower()
        shingle_size = int(getattr(self, '_bloom_shingle_size', 8))

        # Check character-level sliding windows
        if len(text_lower) >= shingle_size:
            for i in range(len(text_lower) - shingle_size + 1):
                shingle = text_lower[i : i + shingle_size]
                if shingle in self._bloom:
                    return True  # Maybe present — continue to Aho-Corasick

        # Also check the full text (for short sensitive terms)
        if text_lower in self._bloom:
            return True

        return False  # Definitely NOT present — skip all expensive checks

    # ─────────────────────────────────────────────
    # Layer 2: Aho-Corasick Exact String Scanner
    # ─────────────────────────────────────────────

    def _build_aho_corasick(self, terms: List[str]) -> None:
        """Build Aho-Corasick finite-state automaton for O(n) multi-pattern matching."""
        try:
            import ahocorasick

            self._automaton = ahocorasick.Automaton()
            for idx, term in enumerate(terms):
                self._automaton.add_word(term.lower(), (idx, term))
            self._automaton.make_automaton()
            logger.info("Aho-Corasick automaton built with %d patterns", len(terms))
        except ImportError:
            logger.warning(
                "pyahocorasick not installed. Aho-Corasick disabled. "
                "Install with: pip install pyahocorasick"
            )

    def _aho_corasick_scan(self, text: str) -> Optional[Dict]:
        """
        Scan text in a single O(n) pass against ALL sensitive terms simultaneously.
        Returns match info if found, None otherwise.
        """
        if self._automaton is None:
            return None

        text_lower = text.lower()
        for end_index, (pattern_idx, original_term) in self._automaton.iter(text_lower):
            start_index = end_index - len(original_term) + 1
            return {
                "blocked": True,
                "reason": "sensitive_term_detected",
                "matched_term": original_term,
                "position": (start_index, end_index + 1),
                "metadata": {"component": "aho_corasick_scanner"},
            }

        return None

    # ─────────────────────────────────────────────
    # Layer 3: Honeypot Trap
    # ─────────────────────────────────────────────

    def _honeypot_check(self, text: str, input_text: Optional[str] = None) -> Optional[Dict]:
        """
        Check if any honeypot tokens appear in the output.
        If a honeypot fires, it's a CONFIRMED attack — log everything.
        """
        if not self._honeypot_set:
            return None

        text_lower = text.lower()
        for token in self._honeypot_set:
            if token in text_lower:
                # Log the attack for threat intelligence
                attack_record = {
                    "timestamp": time.time(),
                    "honeypot_token": token,
                    "output_snippet": text[:200],
                    "input_text": input_text[:200] if input_text else None,
                    "confirmed_attack": True,
                }
                self._honeypot_log.append(attack_record)
                logger.warning(
                    "HONEYPOT TRIGGERED: Token '%s' leaked in output. "
                    "Confirmed prompt injection attack.",
                    token,
                )

                return {
                    "blocked": True,
                    "reason": "honeypot_triggered",
                    "honeypot_token": token,
                    "confirmed_attack": True,
                    "metadata": {"component": "honeypot_trap"},
                }

        return None

    def get_honeypot_log(self) -> List[Dict]:
        """Return the log of all honeypot-triggered attacks for threat intelligence."""
        return self._honeypot_log.copy()

    # ─────────────────────────────────────────────
    # Main Scan Pipeline
    # ─────────────────────────────────────────────

    def scan(
        self,
        output_text: str,
        input_text: Optional[str] = None,
        embedder=None,
        forbidden_vectors: Optional[List[str]] = None,
        vector_db_client: Optional[Callable] = None,
        input_threat_level: float = 0.0,
    ) -> Dict:
        """
        Run the full multi-layer scan pipeline on LLM output.

        Layers execute sequentially and short-circuit on first match:
        1. Bloom Filter → skip expensive checks if definitely clean
        2. Aho-Corasick → exact string matching in O(n)
        3. Honeypot → confirmed attack detection
        4. Embedding → semantic similarity (if embedder provided)

        Args:
            output_text: The LLM's output to scan
            input_text: Original user input (for honeypot logging)
            embedder: sentence-transformers model (for Layer 4)
            forbidden_vectors: List of sensitive strings for embedding comparison
            vector_db_client: BYO-VDB callback
            input_threat_level: Threat score from protect_input

        Returns:
            Dict with scan result
        """
        start_time = time.time()

        # ── Layer 0: BM25 OutputFilter (user-defined sensitive data) ──
        if self._output_filter is not None:
            of_result = self._output_filter.check(output_text)
            if of_result.get("blocked"):
                of_result["reason"] = "output_filter_match"
                of_result["latency_ms"] = (time.time() - start_time) * 1000
                of_result["metadata"] = {"component": "output_filter_bm25"}
                return of_result

        # ── Layer 1: Bloom Filter Pre-Gate ──
        if not self._bloom_check(output_text):
            # Bloom filter says "definitely clean" — skip all heavy checks
            latency_ms = (time.time() - start_time) * 1000
            return {
                "blocked": False,
                "output": output_text,
                "latency_ms": latency_ms,
                "fast_path": True,
                "metadata": {"component": "bloom_filter_pass"},
            }

        # ── Layer 2: Aho-Corasick Exact Match ──
        ac_result = self._aho_corasick_scan(output_text)
        if ac_result:
            ac_result["latency_ms"] = (time.time() - start_time) * 1000
            return ac_result

        # ── Layer 3: Honeypot Trap ──
        hp_result = self._honeypot_check(output_text, input_text)
        if hp_result:
            hp_result["latency_ms"] = (time.time() - start_time) * 1000
            return hp_result

        # ── Layer 4: Embedding Similarity Guard ──
        if embedder and (forbidden_vectors or vector_db_client):
            embed_result = self._embedding_scan(
                output_text,
                embedder,
                forbidden_vectors,
                vector_db_client,
                input_threat_level,
            )
            if embed_result:
                embed_result["latency_ms"] = (time.time() - start_time) * 1000
                return embed_result
                
        # ── Layer 5: Web Search Fallback (Optional) ──
        # Check if enabled on the engine dynamically, via Shield kwargs
        if getattr(self, "enable_web_fallback", False):
            web_result = self._web_search_fallback(output_text)
            if web_result:
                web_result["latency_ms"] = (time.time() - start_time) * 1000
                return web_result

        # ── All Clear ──
        latency_ms = (time.time() - start_time) * 1000
        return {
            "blocked": False,
            "output": output_text,
            "latency_ms": latency_ms,
            "metadata": {"component": "output_engine_passed"},
        }

    def _embedding_scan(
        self,
        output_text: str,
        embedder,
        forbidden_vectors: Optional[List[str]],
        vector_db_client: Optional[Callable],
        input_threat_level: float,
    ) -> Optional[Dict]:
        """Layer 4: Semantic similarity check using embeddings."""
        try:
            from sentence_transformers import util

            # Dynamic threshold based on input suspiciousness
            threshold = self.embedding_threshold
            if input_threat_level > 0.8:
                threshold = 0.60
            elif input_threat_level > 0.6:
                threshold = 0.70

            # Embed the output once
            output_emb = embedder.encode(output_text, convert_to_tensor=True)
            max_score = 0.0

            # BYO-VDB takes priority
            if vector_db_client:
                max_score = float(vector_db_client(output_emb.tolist()))
            elif forbidden_vectors:
                forbidden_embs = embedder.encode(forbidden_vectors, convert_to_tensor=True)
                cosine_scores = util.cos_sim(output_emb, forbidden_embs)[0]
                max_score = float(cosine_scores.max())

            if max_score > threshold:
                return {
                    "blocked": True,
                    "reason": "embedding_match_forbidden",
                    "similarity_score": max_score,
                    "threshold": threshold,
                    "metadata": {"component": "embedding_guard"},
                }
            else:
                return {
                    "blocked": False,
                    "output": output_text,
                    "similarity_score": max_score,
                    "threshold": threshold,
                    "metadata": {"component": "embedding_guard_passed"},
                }

        except Exception as e:
            logger.warning("Embedding scan failed: %s", e)
            return None

    # ─────────────────────────────────────────────
    # Layer 5: Web Search Fallback
    # ─────────────────────────────────────────────

    def _web_search_fallback(self, output_text: str) -> Optional[Dict]:
        """
        Layer 5: Web Search Fallback.
        Checks if the LLM output (specifically a highly sensitive phrase) is available on the public internet.
        If it's NOT on the public internet, but the LLM is generating it, it implies an internal data leak.
        """
        try:
            from duckduckgo_search import DDGS
            
            # Simple heuristic: only search if the text looks like a factual statement or specific entity
            # Searching entire paragraphs is slow and gives bad results.
            # In a real system, you'd extract entities/noun phrases. Here we take the first 100 chars.
            search_query = output_text[:100].replace('\n', ' ').strip()
            
            if len(search_query) < 10:
                return None # Too short to search meaningfully
                
            start_time = time.time()
            with DDGS() as ddgs:
                # Get top 3 web results
                results = list(ddgs.text(search_query, max_results=3))
            
            # If no results are found for a highly specific query, it might be internal/private
            if not results:
                logger.warning("Web search fallback triggered: No public results found for query. Potential internal leak.")
                return {
                    "blocked": True,
                    "reason": "web_search_fallback_failed",
                    "details": "Content not found on public internet, potential internal data leak.",
                    "metadata": {"component": "web_search_fallback", "latency_ms": (time.time() - start_time) * 1000}
                }
            
            # If we found it, it's public knowledge, so let it pass.
            return None
            
        except ImportError:
            logger.warning("duckduckgo-search not installed. Web Search Fallback disabled. Install with: pip install duckduckgo-search")
            return None
        except Exception as e:
            logger.warning("Web Search Fallback failed: %s", e)
            return None
