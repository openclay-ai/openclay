"""
OutputFilter — BM25-based Data Loss Prevention.

Matches LLM output against a user-defined corpus of sensitive data
(system prompts, internal docs, credentials, business logic, etc.)
using Google-style inverted index search (BM25) for fast, fuzzy matching.

Usage:
    from openclay.output_filter import OutputFilter

    filt = OutputFilter([
        "You are a financial advisor for Acme Corp...",
        "Internal API: https://api.internal.acme.net/v2",
        "Revenue Q3: $4.2M, projected Q4: $5.1M",
    ])

    result = filt.check("The internal API endpoint is api.internal.acme.net")
    # → {"blocked": True, "score": 12.4, "matched": "Internal API: ..."}
"""

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger("openclay")

# Lazy import to allow graceful degradation
try:
    from rank_bm25 import BM25Plus
    _HAS_BM25 = True
except ImportError:
    _HAS_BM25 = False
    BM25Plus = None


# Basic English stop words
_STOP_WORDS = {
    "the", "a", "an", "and", "or", "but", "if", "then", "else", "when", 
    "is", "are", "was", "were", "be", "been", "being", 
    "in", "on", "at", "to", "for", "with", "by", "of", "from", "up", "down", 
    "i", "you", "he", "she", "it", "we", "they", "my", "your", "his", "her", "its", "our", "their",
    "this", "that", "these", "those", "can", "will", "would", "should", "could"
}

def _tokenize(text: str) -> List[str]:
    """
    Simple whitespace + punctuation tokenizer.
    Lowercases, strips non-alphanumeric chars, and filters basic stop words.
    """
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return [t for t in tokens if t not in _STOP_WORDS]


def _split_sentences(text: str) -> List[str]:
    """
    Split text into sentences for granular matching.
    Handles period, newline, semicolon, and bullet-point separators.
    """
    parts = re.split(r"[.\n;•\-]+", text)
    return [p.strip() for p in parts if len(p.strip()) > 5]


class OutputFilter:
    """
    BM25-based output filter for Data Loss Prevention.

    Accepts a corpus of sensitive data from the developer.
    On each LLM output, queries the corpus using BM25 relevance scoring.
    If any output sentence scores above the threshold → BLOCK.

    Features:
    - Google-style inverted index search (BM25Plus)
    - Sentence-level granularity (catches partial leaks)
    - Hot-add documents at runtime
    - Fast: ~1-5ms per check
    - Graceful degradation if rank-bm25 not installed

    Args:
        sensitive_data: List of sensitive text strings (any length)
        threshold: BM25 relevance score threshold for blocking (default: 8.0)
        min_token_overlap: Minimum overlapping tokens to consider a match (default: 3)
    """

    def __init__(
        self,
        sensitive_data: Optional[List[str]] = None,
        threshold: float = 5.0,
        min_token_overlap: int = 2,
    ):
        self.threshold = threshold
        self.min_token_overlap = min_token_overlap
        self._corpus_sentences: List[str] = []
        self._corpus_tokens: List[List[str]] = []
        self._bm25: Optional[object] = None

        if not _HAS_BM25:
            logger.warning(
                "rank-bm25 not installed — OutputFilter disabled. "
                "Install with: pip install rank-bm25"
            )
            return

        if sensitive_data:
            self._build_index(sensitive_data)

    def _build_index(self, documents: List[str]):
        """
        Build BM25 inverted index from sensitive documents.

        Splits documents into sentences for granular matching,
        then tokenizes each sentence for BM25 indexing.
        """
        self._corpus_sentences = []
        self._corpus_tokens = []

        for doc in documents:
            sentences = _split_sentences(doc)
            if not sentences:
                # Short doc — use the whole thing
                sentences = [doc.strip()]

            for sentence in sentences:
                tokens = _tokenize(sentence)
                if len(tokens) >= 2:  # Skip trivially short fragments
                    self._corpus_sentences.append(sentence)
                    self._corpus_tokens.append(tokens)

        if self._corpus_tokens:
            self._bm25 = BM25Plus(self._corpus_tokens)
            logger.info(
                "OutputFilter indexed %d sentences from %d documents",
                len(self._corpus_sentences),
                len(documents),
            )
        else:
            logger.warning("OutputFilter: no indexable content in sensitive_data")

    def add_documents(self, documents: List[str]):
        """
        Hot-add new sensitive documents to the index.
        Rebuilds the BM25 index with all existing + new data.
        """
        if not _HAS_BM25:
            return

        for doc in documents:
            sentences = _split_sentences(doc)
            if not sentences:
                sentences = [doc.strip()]

            for sentence in sentences:
                tokens = _tokenize(sentence)
                if len(tokens) >= 2:
                    self._corpus_sentences.append(sentence)
                    self._corpus_tokens.append(tokens)

        if self._corpus_tokens:
            self._bm25 = BM25Plus(self._corpus_tokens)

    def check(self, output_text: str) -> Dict:
        """
        Check LLM output against the sensitive data corpus.

        Splits the output into sentences, queries each against the
        BM25 index, and blocks if any sentence scores above threshold.

        Args:
            output_text: The LLM-generated text to check

        Returns:
            Dictionary:
            {
                "blocked": bool,
                "score": float,        # Highest BM25 score
                "matched": str,        # Best-matching sensitive sentence
                "output_sentence": str # The output sentence that matched
            }
        """
        if not _HAS_BM25 or self._bm25 is None or not output_text:
            return {
                "blocked": False,
                "score": 0.0,
                "matched": None,
                "output_sentence": None,
            }

        output_sentences = _split_sentences(output_text)
        if not output_sentences:
            output_sentences = [output_text.strip()]

        best_score = 0.0
        best_match = None
        best_output = None

        for out_sentence in output_sentences:
            query_tokens = _tokenize(out_sentence)
            if len(query_tokens) < 2:
                continue

            scores = self._bm25.get_scores(query_tokens)

            max_idx = scores.argmax() if hasattr(scores, 'argmax') else scores.index(max(scores))
            max_score = float(scores[max_idx])

            if max_score > best_score:
                # Verify minimum token overlap to reduce false positives
                corpus_tokens = self._corpus_tokens[max_idx]
                overlap = len(set(query_tokens) & set(corpus_tokens))

                if overlap >= self.min_token_overlap:
                    best_score = max_score
                    best_match = self._corpus_sentences[max_idx]
                    best_output = out_sentence

        blocked = best_score >= self.threshold

        if blocked:
            logger.warning(
                "OutputFilter BLOCKED: score=%.2f, matched='%s...'",
                best_score,
                (best_match or "")[:60],
            )

        return {
            "blocked": blocked,
            "score": round(best_score, 3),
            "matched": best_match,
            "output_sentence": best_output,
        }

    def get_stats(self) -> Dict:
        """Return index statistics."""
        return {
            "indexed_sentences": len(self._corpus_sentences),
            "bm25_available": _HAS_BM25,
            "threshold": self.threshold,
        }
