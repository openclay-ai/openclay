"""
Configurable Shield Architecture

PyTorch-style composable security shields.
Replace fixed levels (L1/L3/L5/L7) with flexible component composition.
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
import logging
import time

from .telemetry import trace_shield_call

logger = logging.getLogger("promptshield")


@dataclass
class ShieldResult:
    """Standardized result from shield checks"""
    blocked: bool
    reason: Optional[str] = None
    threat_level: float = 0.0
    component: Optional[str] = None
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class ShieldComponent:
    """
    Base class for shield components.
    
    All components must implement check() method.
    """
    
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
        self.metrics = {
            "total_checks": 0,
            "total_blocks": 0,
            "total_time_ms": 0.0
        }
    
    def check(self, text: str, **context) -> ShieldResult:
        """
        Check text for threats.
        
        Args:
            text: Text to check
            **context: Additional context (user_id, session_id, etc.)
        
        Returns:
            ShieldResult
        """
        raise NotImplementedError("Subclasses must implement check()")
    
    def _track_metrics(self, blocked: bool, time_ms: float):
        """Track component metrics"""
        self.metrics["total_checks"] += 1
        if blocked:
            self.metrics["total_blocks"] += 1
        self.metrics["total_time_ms"] += time_ms
    
    def get_stats(self) -> Dict:
        """Get component statistics"""
        return {
            "name": self.name,
            "enabled": self.enabled,
            **self.metrics,
            "block_rate": (
                self.metrics["total_blocks"] / max(1, self.metrics["total_checks"])
            ),
            "avg_time_ms": (
                self.metrics["total_time_ms"] / max(1, self.metrics["total_checks"])
            )
        }


# Component registry for extensibility
_COMPONENT_REGISTRY = {}


def register_component(name: str):
    """
    Decorator to register custom components.
    
    Usage:
        @register_component("my_detector")
        class MyDetector(ShieldComponent):
            def check(self, text, **context):
                return ShieldResult(blocked=False)
    """
    def decorator(cls):
        _COMPONENT_REGISTRY[name] = cls
        return cls
    return decorator


def get_component(name: str, **kwargs) -> ShieldComponent:
    """Get component by name from registry"""
    if name not in _COMPONENT_REGISTRY:
        raise ValueError(f"Component '{name}' not registered. Available: {list(_COMPONENT_REGISTRY.keys())}")
    return _COMPONENT_REGISTRY[name](**kwargs)


class Shield:
    """
    Configurable security shield with PyTorch-style API.
    
    Compose security components declaratively instead of fixed levels.
    
    Examples:
        # Full customization
        shield = Shield(
            patterns=True,
            models=["xgboost"],
            canary=True,
            rate_limiting=True,
            pii_detection=True
        )
        
        # Use presets
        shield = Shield.fast()        # <1ms
        shield = Shield.balanced()    # ~1ms
        shield = Shield.secure()      # ~5ms
        
        # Customize preset
        shield = Shield.balanced(pii_detection=True)
    """
    
    def __init__(
        self,
        # Pattern matching
        patterns: bool = True,
        pattern_db: Optional[str] = None,
        
        # ML models
        models: Optional[List[str]] = None,
        model_threshold: float = 0.7,
        
        # Security features
        canary: bool = False,
        canary_mode: str = "crypto",  # "simple" | "crypto"
        
        rate_limiting: bool = False,
        rate_limit_base: int = 100,
        
        session_tracking: bool = False,
        session_history: int = 10,
        
        pii_detection: bool = False,
        pii_redaction: str = "smart",  # "smart" | "mask" | "partial"
        
        # Model security
        verify_models: bool = False,
        
        # Allowlist / Custom rules
        allowlist: Optional[List[str]] = None,
        allowlist_file: Optional[str] = None,
        custom_patterns: Optional[List[str]] = None,
        custom_patterns_file: Optional[str] = None,
        
        # Webhooks (v2.6.0)
        webhook_url: Optional[str] = None,
        webhook_min_threat: float = 0.5,
        webhook_include_input: bool = False,
        
        # Performance
        cache_predictions: bool = True,
        async_mode: bool = False,
        
        # Embeddings (v3.0.0)
        enforce_embeddings: bool = False,
        embedding_model: str = "all-MiniLM-L6-v2",
        
        # Output Engine (v3.0.0)
        sensitive_terms: Optional[List[str]] = None,
        honeypot_tokens: Optional[List[str]] = None,
        enable_web_fallback: bool = False,
        
        # OutputFilter — user-defined sensitive data DLP (v3.1.0)
        output_filter: Optional[List[str]] = None,
        output_filter_threshold: float = 5.0,
        
        # Custom components
        custom_components: Optional[List[str]] = None,
        
        **kwargs
    ):
        """
        Initialize configurable shield.
        
        Args:
            patterns: Enable pattern matching
            pattern_db: Custom pattern database path
            models: List of ML models to use
            model_threshold: Confidence threshold for ML
            canary: Enable canary tokens
            canary_mode: "simple" or "crypto"
            rate_limiting: Enable adaptive rate limiting
            rate_limit_base: Base rate limit (req/min)
            session_tracking: Enable session anomaly detection
            session_history: Messages to track per session
            pii_detection: Enable PII detection
            pii_redaction: Redaction mode
            verify_models: Verify model signatures
            allowlist: List of exact phrases to never block
            custom_patterns: List of regex patterns to always block
            cache_predictions: Cache ML predictions
            async_mode: Enable async operations
            custom_components: List of custom component names
        """
        # Resolve allowlist from file if provided
        merged_allowlist = list(allowlist or [])
        if allowlist_file:
            from .config import load_allowlist_file
            merged_allowlist.extend(load_allowlist_file(allowlist_file))
        
        # Resolve custom patterns from file if provided
        merged_patterns = list(custom_patterns or [])
        if custom_patterns_file:
            import os
            if not os.path.exists(custom_patterns_file):
                raise FileNotFoundError(f"Custom patterns file not found: {custom_patterns_file}")
            with open(custom_patterns_file, "r", encoding="utf-8") as f:
                merged_patterns.extend(
                    line.strip() for line in f 
                    if line.strip() and not line.startswith("#")
                )
        
        self.config = {
            "patterns": patterns,
            "pattern_db": pattern_db or "promptshield/attack_db",
            "models": models or [],
            "model_threshold": model_threshold,
            "canary": canary,
            "canary_mode": canary_mode,
            "rate_limiting": rate_limiting,
            "rate_limit_base": rate_limit_base,
            "session_tracking": session_tracking,
            "session_history": session_history,
            "pii_detection": pii_detection,
            "pii_redaction": pii_redaction,
            "verify_models": verify_models,
            "allowlist": [p.lower().strip() for p in merged_allowlist],
            "custom_patterns": merged_patterns,
            "webhook_url": webhook_url,
            "webhook_min_threat": webhook_min_threat,
            "webhook_include_input": webhook_include_input,
            "cache_predictions": cache_predictions,
            "async_mode": async_mode,
            "enforce_embeddings": enforce_embeddings,
            "embedding_model": embedding_model,
            **kwargs
        }
        
        # Initialize webhook notifier (v2.6.0)
        self.webhook = None
        if webhook_url:
            from .webhooks import WebhookNotifier
            self.webhook = WebhookNotifier(
                url=webhook_url,
                min_threat_level=webhook_min_threat,
                include_input=webhook_include_input,
            )
        
        # Initialize ML attributes (must be before _build_pipeline)
        self.models = {}
        self.vectorizer = None
        
        # Build component pipeline
        self.components = []
        self._build_pipeline(custom_components or [])
        
        # Load ML models if configured
        if self.config["models"]:
            self._load_ml_models()
            
        # Load Embeddings if configured
        if self.config.get("enforce_embeddings"):
            self._load_embeddings()
        else:
            self.embedder = None
        
        # Initialize subsystems
        self._init_subsystems()
        
        # Build OutputFilter if user supplied sensitive data (v3.1.0)
        self._output_filter = None
        if output_filter:
            try:
                from .output_filter import OutputFilter
                self._output_filter = OutputFilter(
                    sensitive_data=output_filter,
                    threshold=output_filter_threshold,
                )
            except ImportError:
                logger.warning(
                    "rank-bm25 not installed — OutputFilter disabled. "
                    "Install with: pip install rank-bm25"
                )
        
        # Initialize Output Engine (v3.0.0 — multi-layer DLP pipeline)
        self.output_engine = None
        if sensitive_terms or honeypot_tokens or enable_web_fallback or self._output_filter:
            from .output_engine import OutputEngine
            self.output_engine = OutputEngine(
                sensitive_terms=sensitive_terms,
                honeypot_tokens=honeypot_tokens,
                embedding_threshold=0.78,
                output_filter=self._output_filter,
            )
            # Enable Layer 5: Web Search Fallback if requested
            if enable_web_fallback:
                self.output_engine.enable_web_fallback = True
    
    def _build_pipeline(self, custom_components: List[str]):
        """Build component pipeline based on config"""
        # Import components (lazy loading)
        from .pattern_manager import PatternManager
        
        # 1. Rate limiting (first layer of defense)
        if self.config["rate_limiting"]:
            from .rate_limiting import AdaptiveRateLimiter
            self.rate_limiter = AdaptiveRateLimiter(
                base_limit=self.config["rate_limit_base"]
            )
        
        # 2. Pattern matching (fast check)
        if self.config["patterns"]:
            import os
            pkg_dir = os.path.dirname(os.path.abspath(__file__))
            pattern_db = self.config["pattern_db"]
            # If pattern_db is the old hardcoded path, use package-relative path
            if pattern_db == "promptshield/attack_db":
                pattern_db = os.path.join(pkg_dir, "attack_db")
            self.pattern_manager = PatternManager(pattern_db)
        
        # 3. Session anomaly detection
        if self.config["session_tracking"]:
            from .session_anomaly import SessionAnomalyDetector
            self.session_detector = SessionAnomalyDetector(
                history_window=self.config["session_history"]
            )
        
        # 4. ML models — loaded in __init__ after _build_pipeline() returns
        # (removed duplicate _load_ml_models() call that was here)
        
        # 5. Canary generation
        if self.config["canary"]:
            if self.config["canary_mode"] == "crypto":
                from .security.canary_crypto import CryptoCanaryGenerator
                self.canary_generator = CryptoCanaryGenerator()
            else:
                from .methods import generate_canary
                self.canary_generator = None  # Use simple method
        
        # 6. PII detection
        if self.config["pii_detection"]:
            from .pii import ContextualPIIDetector
            self.pii_detector = ContextualPIIDetector()
        
        # 7. Custom components
        for comp_name in custom_components:
            comp = get_component(comp_name)
            self.components.append(comp)
    
    def _init_subsystems(self):
        """Initialize subsystems (caching, async, etc.)"""
        self.prediction_cache = {} if self.config["cache_predictions"] else None
        
    def _load_ml_models(self):
        """Load configured ML models"""
        self.models = {}
        import os
        import joblib
        
        models_dir = os.path.join(os.path.dirname(__file__), "models")
        
        # 1. Load Vectorizer (shared TF-IDF, trained on core split — zero leakage)
        try:
            vec_path = os.path.join(models_dir, "tfidf_core.pkl")
            if os.path.exists(vec_path):
                self.vectorizer = joblib.load(vec_path)
            else:
                logger.warning("Vectorizer not found at %s. ML models disabled.", vec_path)
                return
        except Exception as e:
            logger.warning("Failed to load vectorizer: %s", e)
            return

        # 2. Load Models
        # Filename map for leak-free models trained on core dataset
        filename_map = {
            "logistic_regression": "logistic_regression.pkl",
            "random_forest":       "rf_core.pkl",
            "linear_svc":          "linear_svc.pkl",
            "gradient_boosting":   "gradient_boosting.pkl",
            "svm":                 "linear_svc.pkl",
        }

        for model_name in self.config["models"]:
            try:
                if model_name in ("semantic", "transformer"):
                    # Placeholder for future transformer integration
                    pass

                elif model_name == "deberta":
                    # Auto-download DeBERTa from HuggingFace Hub on first use
                    try:
                        from transformers import pipeline as hf_pipeline
                        deberta_pipe = hf_pipeline(
                            "text-classification",
                            model="neuralchemy/prompt-injection-deberta",
                            device=-1,  # CPU by default; set to 0 for GPU
                            truncation=True,
                            max_length=256,
                        )
                        self.models["deberta"] = {
                            "model": deberta_pipe,
                            "type": "deberta",
                            "status": "active"
                        }
                        logger.info("Loaded deberta (neuralchemy/prompt-injection-deberta)")
                    except Exception as e:
                        logger.warning("Failed to load DeBERTa: %s", e)

                else:
                    fname = filename_map.get(model_name, f"{model_name}.pkl")
                    model_path = os.path.join(models_dir, fname)

                    if os.path.exists(model_path):
                        loaded_model = joblib.load(model_path)
                        self.models[model_name] = {
                            "model": loaded_model,
                            "type": "sklearn",
                            "status": "active"
                        }
                        logger.info("Loaded %s (%s)", model_name, fname)
                    else:
                        logger.warning("Model file not found: %s", fname)

            except Exception as e:
                logger.warning("Failed to load model %s: %s", model_name, e)
                
    def _load_embeddings(self):
        """Load sentence-transformers model for output embedding protection.
        Degrades gracefully if loading fails — embedding guard is disabled, not crashed."""
        self.embedder = None
        self._embedding_errors = 0
        try:
            from sentence_transformers import SentenceTransformer
            self.embedder = SentenceTransformer(self.config["embedding_model"])
            logger.info("Loaded embedding model (%s)", self.config['embedding_model'])
        except ImportError:
            logger.warning("sentence-transformers not installed. Embedding guard disabled. Install with: pip install sentence-transformers")
        except Exception as e:
            logger.warning("Failed to load embedding model: %s — embedding guard disabled", e)

    def _check_ml_models(self, text: str) -> float:
        """
        Check text against ML models with ensemble voting.

        Uses majority voting + probability averaging for robust predictions.
        DeBERTa uses a HuggingFace pipeline and is handled separately.

        Returns:
            Threat score (0.0 - 1.0)
        """
        try:
            predictions = []
            probabilities = []
            
            # Pre-compute TF-IDF vectorization only if sklearn models are present
            X = None
            if hasattr(self, 'vectorizer') and any(m.get("type") == "sklearn" for m in self.models.values()):
                X = self.vectorizer.transform([text])

            for model_name, model_data in self.models.items():
                if model_data.get("status") != "active":
                    continue
                
                model = model_data.get("model")
                if model is None:
                    continue

                try:
                    if model_data.get("type") == "deberta":
                        # DeBERTa HuggingFace Pipeline
                        result = model(text[:512])[0]
                        
                        # In HF pipelines, label 'LABEL_1' usually means positive class (attack)
                        # We need to compute the probability of it being an *attack*
                        prob = result["score"] if result["label"] in ("LABEL_1", "1", 1) else (1.0 - result["score"])
                        
                        predictions.append(1 if prob >= 0.5 else 0)
                        probabilities.append(prob)
                        
                    elif model_data.get("type") == "sklearn" and X is not None:
                        # Scikit-Learn Model
                        pred = model.predict(X)[0]
                        predictions.append(int(pred))
                        
                        if hasattr(model, 'predict_proba'):
                            prob_arr = model.predict_proba(X)[0]
                            # prob_arr[1] is the probability of class 1 (attack)
                            prob = prob_arr[1] if len(prob_arr) > 1 else prob_arr[0]
                            probabilities.append(float(prob))
                        else:
                            # E.g., LinearSVC doesn't always have predict_proba enabled
                            probabilities.append(float(pred))
                            
                except Exception as e:
                    logger.warning("Model %s prediction failed: %s", model_name, e)
                    continue

            if not predictions:
                return 0.0

            # Ensemble Logic
            attack_votes = sum(predictions)
            vote_ratio   = attack_votes / len(predictions)
            
            # Penalize highly confident false positives by requiring a threshold of votes
            if vote_ratio < 0.3:
                # If very few models voted 'attack' (e.g. 1 out of 4), heavily penalize the probability average
                # This prevents one overfitted scikit-learn model from dragging the score to 0.95
                avg_prob = (sum(probabilities) / len(probabilities)) * 0.3
            else:
                avg_prob = sum(probabilities) / len(probabilities) if probabilities else 0.0
            
            # Weighted ensemble score: heavily favor actual votes over pure raw probabilities
            threat_score = (0.7 * vote_ratio) + (0.3 * avg_prob)
            return float(min(threat_score, 1.0))

        except Exception as e:
            logger.warning("ML ensemble check failed: %s", e)
            return 0.0

    
    # ========================================
    # Factory Methods (Presets)
    # ========================================
    
    @classmethod
    def fast(cls, **kwargs):
        """
        Fast preset - Pattern matching only.
        
        Latency: <1ms
        Features: Pattern matching
        
        Args:
            **kwargs: Override default settings
        """
        defaults = {
            "patterns": True,
            "canary": False,
            "rate_limiting": False,
            "session_tracking": False,
            "pii_detection": False,
        }
        defaults.update(kwargs)
        return cls(**defaults)
    
    @classmethod
    def balanced(cls, **kwargs):
        """
        Balanced preset - Production default.
        
        Latency: ~1-2ms
        Features: Patterns + Session tracking
        
        Args:
            **kwargs: Override default settings
        """
        defaults = {
            "patterns": True,
            "canary": False,
            "rate_limiting": False,
            "session_tracking": True,
            "session_history": 10,
            "pii_detection": False,
        }
        defaults.update(kwargs)
        return cls(**defaults)
    
    @classmethod
    def strict(cls, **kwargs):
        """
        Strict preset - High security with ML.
        
        Latency: ~7-10ms
        Features: Patterns + 1 ML Model + Rate limiting + Session tracking + PII
        ML: Logistic Regression (fast)
        
        Args:
            **kwargs: Override default settings
        """
        defaults = {
            "patterns": True,
            "canary": False,
            "rate_limiting": True,
            "rate_limit_base": 50,
            "session_tracking": True,
            "session_history": 20,
            "pii_detection": True,
            "pii_redaction": "mask",
        }
        # Add 1 ML model if not overridden
        if "models" not in kwargs:
            defaults["models"] = ["logistic_regression"]
        
        defaults.update(kwargs)
        return cls(**defaults)
    
    @classmethod
    def secure(cls, **kwargs):
        """
        Secure preset - Maximum protection with full ML ensemble.
        
        Latency: ~12-15ms
        Features: All protections + 3 ML Models (ensemble voting)
        ML: Logistic Regression, Random Forest, SVM
        
        Args:
            **kwargs: Override default settings
        """
        defaults = {
            "patterns": True,
            "canary": True,
            "canary_mode": "crypto",
            "rate_limiting": True,
            "rate_limit_base": 50,
            "session_tracking": True,
            "session_history": 20,
            "pii_detection": True,
            "pii_redaction": "smart",
            "verify_models": False,
        }
        # Full ML ensemble: Random Forest + LR + LinearSVC + Gradient Boosting
        if "models" not in kwargs:
            defaults["models"] = ["random_forest", "logistic_regression", "linear_svc", "gradient_boosting"]
        
        defaults.update(kwargs)
        return cls(**defaults)
    
    @trace_shield_call("input")
    def protect_input(
        self,
        user_input: str,
        system_context: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        **context
    ) -> Dict:
        """
        Protect user input.
        
        Args:
            user_input: User's input text
            system_context: System prompt/context
            user_id: User identifier (for rate limiting)
            session_id: Session identifier (for tracking)
            **context: Additional context
        
        Returns:
            Dictionary with protection result
        """
        start_time = time.time()

        # Track per-layer scores for breakdown
        threat_breakdown = {
            "pattern_score": 0.0,
            "ml_score":      0.0,
            "session_score": 0.0,
        }

        # 0a. Allowlist — skip all checks for known-safe phrases
        if self.config["allowlist"]:
            input_lower = user_input.lower().strip()
            for safe_phrase in self.config["allowlist"]:
                if safe_phrase in input_lower:
                    return {
                        "blocked": False,
                        "reason": "allowlisted",
                        "threat_level": 0.0,
                        "threat_breakdown": threat_breakdown,
                        "metadata": {"component": "allowlist", "matched": safe_phrase},
                    }

        # 0b. Custom patterns — always block on match
        if self.config["custom_patterns"]:
            import re
            for pattern in self.config["custom_patterns"]:
                try:
                    if re.search(pattern, user_input, re.IGNORECASE):
                        result = {
                            "blocked": True,
                            "reason": "custom_pattern",
                            "threat_level": 1.0,
                            "threat_breakdown": threat_breakdown,
                            "metadata": {"component": "custom_pattern", "pattern": pattern},
                        }
                        if self.webhook:
                            self.webhook.notify(result, user_input)
                        return result
                except re.error:
                    pass

        # 1. Rate limiting check
        if self.config["rate_limiting"] and user_id:
            rate_result = self.rate_limiter.check_limit(user_id, threat_level=0.0)
            if not rate_result["allowed"]:
                return {
                    "blocked": True,
                    "reason": "rate_limit_exceeded",
                    "retry_after": rate_result["retry_after"],
                    "metadata": {"component": "rate_limiter"}
                }

        # 2. Pattern matching
        threat_level = 0.0
        if self.config["patterns"]:
            matched, score, rule = self.pattern_manager.match(user_input)
            threat_breakdown["pattern_score"] = round(score, 3)
            threat_level = max(threat_level, score)

            if matched:
                result = {
                    "blocked": True,
                    "reason": "pattern_match",
                    "rule": rule,
                    "threat_level": score,
                    "threat_breakdown": threat_breakdown,
                    "metadata": {"component": "pattern_matcher"}
                }
                if self.webhook:
                    self.webhook.notify(result, user_input)
                return result

        # 3. ML model prediction
        if self.config["models"]:
            ml_threat = self._check_ml_models(user_input)
            threat_breakdown["ml_score"] = round(ml_threat, 3)
            threat_level = max(threat_level, ml_threat)

            if ml_threat >= self.config["model_threshold"]:
                result = {
                    "blocked": True,
                    "reason": "ml_detection",
                    "threat_level": ml_threat,
                    "threat_breakdown": threat_breakdown,
                    "metadata": {"component": "ml_model"}
                }
                if self.webhook:
                    self.webhook.notify(result, user_input)
                return result

        # 4. Session anomaly detection
        if self.config["session_tracking"] and session_id:
            shield_result = {"threat_level": threat_level, "blocked": False}
            session_result = self.session_detector.analyze(
                session_id, user_input, shield_result
            )
            threat_breakdown["session_score"] = round(
                session_result.get("session_threat", 0.0), 3
            )

            if session_result["action"] == "block_session":
                result = {
                    "blocked": True,
                    "reason": session_result["reason"],
                    "session_threat": session_result["session_threat"],
                    "threat_breakdown": threat_breakdown,
                    "metadata": {"component": "session_anomaly"}
                }
                if self.webhook:
                    self.webhook.notify(result, user_input)
                return result
        
        # 5. Generate canary (if enabled)
        canary_data = None
        secured_context = system_context
        
        if self.config["canary"]:
            session_id = session_id or f"default_{int(time.time())}"
            
            if self.config["canary_mode"] == "crypto":
                canary_data = self.canary_generator.generate(system_context, session_id)
                secured_context = self.canary_generator.inject_into_prompt(
                    system_context, canary_data
                )
            else:
                from .methods import generate_canary, inject_canary
                canary_data = {"canary": generate_canary()}
                secured_context = inject_canary(system_context, canary_data["canary"])
        
        # Update rate limiter with final threat
        if self.config["rate_limiting"] and user_id:
            self.rate_limiter.check_limit(user_id, threat_level=threat_level)
        
        latency_ms = (time.time() - start_time) * 1000
        
        return {
            "blocked": False,
            "secured_context": secured_context,
            "canary": canary_data,
            "threat_level": threat_level,
            "latency_ms": latency_ms,
            "metadata": {
                "components_executed": self._get_active_components()
            }
        }
    
    @trace_shield_call("output")
    def protect_output(
        self,
        model_output: str,
        canary: Optional[Dict] = None,
        user_id: Optional[str] = None,
        user_input: Optional[str] = None,
        enforce_embeddings: bool = False,
        forbidden_vectors: Optional[List[str]] = None,
        vector_db_client: Optional[Callable[[List[float]], float]] = None,
        input_threat_level: float = 0.0,
        **context
    ) -> Dict:
        """
        Protect model output.
        
        Args:
            model_output: LLM output text
            canary: Canary data from protect_input
            user_id: User identifier
            user_input: Original user input (for PII context)
            enforce_embeddings: Enable matching output against forbidden_vectors or custom DB
            forbidden_vectors: List of strings (e.g. original prompt) to not leak (Small Scale)
            vector_db_client: A function that takes an embedding list and returns the max similarity score (Enterprise BYO-VDB)
            input_threat_level: From protect_input, dynamically lowers thresholds if suspicious
            **context: Additional context
        
        Returns:
            Dictionary with protection result
        """
        start_time = time.time()
        
        # 1. Canary leak detection
        if self.config["canary"] and canary:
            if self.config["canary_mode"] == "crypto":
                from .security.canary_crypto import verify_canary_leak
                is_leaked, reason = verify_canary_leak(model_output, canary)
                
                if is_leaked:
                    return {
                        "blocked": True,
                        "reason": f"canary_leak:{reason}",
                        "metadata": {"component": "canary_detector"}
                    }
            else:
                from .methods import detect_canary
                if detect_canary(model_output, canary.get("canary", "")):
                    return {
                        "blocked": True,
                        "reason": "canary_leak",
                        "metadata": {"component": "canary_detector"}
                    }
        
        # 2. PII detection
        if self.config["pii_detection"]:
            from .pii import PIIContext, smart_redact
            from .pii.contextual_detector import extract_user_pii
            
            # Build PII context
            user_pii = extract_user_pii(user_input) if user_input else []
            pii_context = PIIContext(
                user_id=user_id or "unknown",
                user_provided_pii=user_pii
            )
            
            result = self.pii_detector.scan_and_classify(model_output, pii_context)
            
            if result["action"] == "block":
                return {
                    "blocked": True,
                    "reason": "pii_leak_critical",
                    "summary": result["summary"],
                    "metadata": {"component": "pii_detector"}
                }
            
            elif result["action"] == "warn":
                # Redact and allow
                redacted_output = smart_redact(model_output, result["findings"])
                
                latency_ms = (time.time() - start_time) * 1000
                
                return {
                    "blocked": False,
                    "output": redacted_output,
                    "redacted": True,
                    "pii_summary": result["summary"],
                    "latency_ms": latency_ms,
                    "metadata": {"component": "pii_detector"}
                }

        # 3. Output Engine — Multi-layer DLP pipeline (v3.0.0)
        if getattr(self, 'output_engine', None):
            engine_result = self.output_engine.scan(
                output_text=model_output,
                input_text=user_input,
                embedder=getattr(self, 'embedder', None),
                forbidden_vectors=forbidden_vectors,
                vector_db_client=vector_db_client,
                input_threat_level=input_threat_level,
            )
            if engine_result.get("blocked"):
                engine_result["latency_ms"] = (time.time() - start_time) * 1000
                return engine_result
            # Bloom filter fast-path: definitely clean
            if engine_result.get("fast_path"):
                latency_ms = (time.time() - start_time) * 1000
                return {
                    "blocked": False,
                    "output": model_output,
                    "latency_ms": latency_ms,
                    "metadata": engine_result.get("metadata", {}),
                }

        # 4. Legacy Embedding Guard (fallback for users without OutputEngine)
        do_embed = enforce_embeddings or self.config.get("enforce_embeddings")
        if do_embed and (forbidden_vectors or vector_db_client) and getattr(self, 'embedder', None) and not getattr(self, 'output_engine', None):
            from sentence_transformers import util
            
            # Dynamic threshold based on input suspiciousness (session state propagation)
            threshold = 0.78
            if input_threat_level > 0.8:
                threshold = 0.60
            elif input_threat_level > 0.6:
                threshold = 0.70
                
            try:
                # 1. Embed the LLM's Output once
                output_emb = self.embedder.encode(model_output, convert_to_tensor=True)
                
                max_score = 0.0
                
                # 2. Check against custom VectorDB (Enterprise BYO-VDB) if provided
                if vector_db_client:
                    # Provide the embedding as a standard python list to the engineer's callback
                    max_score = float(vector_db_client(output_emb.tolist()))
                
                # 3. Fallback: check against small local array if provided
                elif forbidden_vectors:
                    forbidden_embs = self.embedder.encode(forbidden_vectors, convert_to_tensor=True)
                    cosine_scores = util.cos_sim(output_emb, forbidden_embs)[0]
                    max_score = float(cosine_scores.max())
                
                # 4. Enforce threshold
                if max_score > threshold:
                    return {
                        "blocked": True,
                        "reason": "embedding_match_forbidden",
                        "similarity_score": max_score,
                        "threshold": threshold,
                        "metadata": {"component": "embedding_guard"}
                    }
                else:
                    # Provide metadata even if not blocked for testing
                    latency_ms = (time.time() - start_time) * 1000
                    return {
                        "blocked": False,
                        "output": model_output,
                        "latency_ms": latency_ms,
                        "similarity_score": max_score,
                        "threshold": threshold,
                        "metadata": {"component": "embedding_guard_passed"}
                    }
            except Exception as e:
                logger.warning("Embedding check failed: %s", e)

        latency_ms = (time.time() - start_time) * 1000
        
        return {
            "blocked": False,
            "output": model_output,
            "latency_ms": latency_ms
        }
    
    def protect_stream_chunk(
        self,
        chunk: str,
        buffer: Optional[str] = None,
        canary: Optional[Dict] = None,
        **context,
    ) -> Dict:
        """
        Synchronously check a single streaming chunk.
        
        Args:
            chunk: Current text chunk from stream
            buffer: Accumulated text so far (for canary detection)
            canary: Canary data from protect_input
            **context: Additional context
            
        Returns:
            {"blocked": bool, "text": str, "reason": str|None}
        """
        full_text = (buffer or "") + chunk

        # Canary check
        if canary and self.config["canary"]:
            if self.config["canary_mode"] == "crypto":
                from .security.canary_crypto import verify_canary_leak
                is_leaked, reason = verify_canary_leak(full_text, canary)
                if is_leaked:
                    return {
                        "blocked": True,
                        "text": "",
                        "reason": f"canary_leak:{reason}",
                    }
            else:
                from .methods import detect_canary
                if detect_canary(full_text, canary.get("canary", "")):
                    return {
                        "blocked": True,
                        "text": "",
                        "reason": "canary_leak",
                    }

        # PII check on chunk (synchronous)
        if self.config["pii_detection"]:
            from .methods import pii_scan
            findings = pii_scan(full_text)
            if findings:
                return {
                    "blocked": True,
                    "text": "",
                    "reason": "pii_in_stream",
                    "findings": findings,
                }

        return {"blocked": False, "text": chunk, "reason": None}

    def protect_stream(
        self,
        generator,
        canary: Optional[Dict] = None,
        **context,
    ):
        """
        Wrap a synchronous text generator to automatically scan for threats mid-generation.
        Raises StreamBlockedError if a threat is detected.
        
        Args:
            generator: Synchronous iterable yielding strings
            canary: Canary data from protect_input
            **context: Additional context
            
        Yields:
            str: The safe chunks
            
        Raises:
            StreamBlockedError: If the stream contains restricted content (e.g. PII leak, Canary leak)
        """
        buffer = ""
        for chunk in generator:
            result = self.protect_stream_chunk(chunk, buffer, canary, **context)
            if result.get("blocked"):
                if getattr(self, "webhook", None):
                    # Ensure webhook is triggered on blocked streams too
                    self.webhook.notify(result, None)
                from .exceptions import StreamBlockedError
                raise StreamBlockedError(reason=result["reason"], result_dict=result)
            
            buffer += chunk
            yield result["text"]

    @trace_shield_call("tool_call")
    def protect_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        allowed_tools: Optional[List[str]] = None,
        **context
    ) -> Dict:
        """
        Protect MCP/Agent tool calls from malicious argument payloads.
        """
        import json
        start_time = time.time()
        
        # 1. Check allowed tools
        if allowed_tools is not None and tool_name not in allowed_tools:
            result = {
                "blocked": True,
                "reason": "tool_not_allowed",
                "tool_name": tool_name
            }
            if getattr(self, "webhook", None):
                self.webhook.notify(result, f"Tool Call: {tool_name}")
            return result
            
        # 2. Serialize arguments for scanning (Extract values to avoid JSON syntax confusing ML)
        def flatten_dict(d):
            vals = []
            if isinstance(d, dict):
                for v in d.values():
                    vals.extend(flatten_dict(v))
            elif isinstance(d, list):
                for v in d:
                    vals.extend(flatten_dict(v))
            else:
                vals.append(str(d))
            return vals
            
        try:
            arg_string = " ".join(flatten_dict(arguments))
        except Exception:
            arg_string = str(arguments)
            
        # 3. Fast Pattern Matching
        if self.config["patterns"]:
            matched, score, rule = self.pattern_manager.match(arg_string)
            if matched:
                result = {
                    "blocked": True,
                    "reason": "pattern_match",
                    "rule": rule,
                    "threat_level": score,
                    "metadata": {"component": "tool_guard_patterns", "tool_name": tool_name}
                }
                if getattr(self, "webhook", None):
                    self.webhook.notify(result, arg_string)
                return result
                
        # 4. ML Models
        if self.config["models"]:
            ml_threat = self._check_ml_models(arg_string)
            if ml_threat >= self.config["model_threshold"]:
                result = {
                    "blocked": True,
                    "reason": "ml_detection",
                    "threat_level": ml_threat,
                    "metadata": {"component": "tool_guard_ml", "tool_name": tool_name}
                }
                if getattr(self, "webhook", None):
                    self.webhook.notify(result, arg_string)
                return result
                
        latency_ms = (time.time() - start_time) * 1000
        return {
            "blocked": False,
            "threat_level": 0.0,
            "latency_ms": latency_ms
        }
    
    def _get_active_components(self) -> List[str]:
        """Get list of active components"""
        active = []
        if self.config["rate_limiting"]:
            active.append("rate_limiter")
        if self.config["patterns"]:
            active.append("pattern_matcher")
        if self.config["models"]:
            active.append("ml_models")
        if self.config["session_tracking"]:
            active.append("session_anomaly")
        if self.config["canary"]:
            active.append("canary")
        if self.config["pii_detection"]:
            active.append("pii_detector")
        return active
    
    def get_stats(self) -> Dict:
        """Get shield statistics (redacts sensitive config values)"""
        # Redact sensitive fields from config before exposing
        _REDACTED_KEYS = {
            "webhook_url", "allowlist", "custom_patterns",
            "sensitive_terms", "honeypot_tokens", "output_filter",
        }
        safe_config = {
            k: ("[REDACTED]" if k in _REDACTED_KEYS and v else v)
            for k, v in self.config.items()
        }
        
        stats = {
            "config": safe_config,
            "active_components": self._get_active_components()
        }
        
        # Add component-specific stats
        if self.config["rate_limiting"]:
            stats["rate_limiter"] = self.rate_limiter.get_global_stats()
        
        if self.config["patterns"]:
            stats["pattern_manager"] = self.pattern_manager.get_stats()
        
        if self.config["session_tracking"]:
            stats["session_detector"] = self.session_detector.get_global_stats()
        
        # OutputFilter stats
        if self._output_filter:
            stats["output_filter"] = self._output_filter.get_stats()
        
        return stats
    
    # ============================================
    # Preset Factories (Convenience)
    # ============================================
    
    @classmethod
    def fast(cls, **overrides):
        """
        Fast preset: Pattern-only, <0.5ms
        
        Best for: High-throughput APIs, agent-to-agent
        """
        return cls(
            patterns=True,
            models=None,
            canary=False,
            rate_limiting=False,
            session_tracking=False,
            pii_detection=False,
            **overrides
        )
    
    @classmethod
    def balanced(cls, **overrides):
        """
        Balanced preset: Patterns + canary, ~1ms
        
        Best for: Most production use cases
        """
        return cls(
            patterns=True,
            models=None,  # Can add XGBoost later
            canary=True,
            canary_mode="crypto",
            rate_limiting=False,
            session_tracking=False,
            pii_detection=False,
            **overrides
        )
    
    @classmethod
    def secure(cls, **overrides):
        """
        Secure preset: Full protection, ~5ms
        
        Best for: High-value data, compliance requirements
        """
        return cls(
            patterns=True,
            models=None,  # Can add ML models
            canary=True,
            canary_mode="crypto",
            rate_limiting=True,
            session_tracking=True,
            pii_detection=True,
            pii_redaction="smart",
            **overrides
        )
    
    @classmethod
    def paranoid(cls, **overrides):
        """
        Paranoid preset: Everything enabled, ~10ms
        
        Best for: Maximum security, admin endpoints
        """
        return cls(
            patterns=True,
            models=["xgboost"],  # When available
            canary=True,
            canary_mode="crypto",
            rate_limiting=True,
            rate_limit_base=50,  # Stricter
            session_tracking=True,
            session_history=15,
            pii_detection=True,
            pii_redaction="mask",  # Most aggressive
            verify_models=True,
            **overrides
        )
    
    @classmethod
    def from_config(cls, config_path: str, **overrides):
        """
        Create a Shield from a YAML/JSON config file.
        
        This enables centralized, code-free security policy management.
        Security teams can update policies without touching application code.
        
        Args:
            config_path: Path to .yml, .yaml, or .json config file
            **overrides: Override specific config values
            
        Returns:
            Configured Shield instance
            
        Example YAML (promptshield.yml):
            preset: balanced
            webhook_url: https://hooks.slack.com/...
            allowlist_file: safe_phrases.txt
            custom_patterns:
              - "DROP TABLE"
              - "rm -rf"
        """
        from .config import load_yaml, resolve_config
        
        raw = load_yaml(config_path)
        config = resolve_config(raw)
        
        # Apply overrides
        config.update(overrides)
        
        # Check for preset
        preset = config.pop("preset", None)
        
        if preset:
            factory = {
                "fast": cls.fast,
                "balanced": cls.balanced,
                "strict": cls.strict,
                "secure": cls.secure,
                "paranoid": cls.paranoid,
            }.get(preset)
            
            if not factory:
                raise ValueError(
                    f"Unknown preset '{preset}'. "
                    f"Available: fast, balanced, strict, secure, paranoid"
                )
            
            return factory(**config)
        
        return cls(**config)


# ============================================
# Backward Compatibility (Deprecated)
# ============================================

class InputShield_L5(Shield):
    """
    DEPRECATED: Use Shield.balanced() instead.
    
    Kept for backward compatibility.
    """
    def __init__(self):
        import warnings
        warnings.warn(
            "InputShield_L5 is deprecated. Use Shield.balanced() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(
            patterns=True,
            canary=True,
            canary_mode="simple"  # Old behavior
        )
    
    def run(self, user_input: str, system_prompt: str):
        """Legacy API compatibility"""
        return self.protect_input(user_input, system_prompt)


class OutputShield_L5(Shield):
    """
    DEPRECATED: Use Shield.balanced() instead.
    
    Kept for backward compatibility.
    """
    def __init__(self):
        import warnings
        warnings.warn(
            "OutputShield_L5 is deprecated. Use Shield.balanced() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(
            patterns=False,
            canary=True,
            pii_detection=True
        )
    
    def run(self, model_output: str, canary: str):
        """Legacy API compatibility"""
        canary_data = {"canary": canary}
        return self.protect_output(model_output, canary=canary_data)


class AgentShield_L3(Shield):
    """
    DEPRECATED: Use Shield.fast() instead.
    
    Kept for backward compatibility.
    """
    def __init__(self):
        import warnings
        warnings.warn(
            "AgentShield_L3 is deprecated. Use Shield.fast() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(
            patterns=True,
            canary=False,
            pii_detection=False
        )
    
    def run(self, message: str):
        """Legacy API compatibility"""
        result = self.protect_input(message, "")
        return {
            "block": result["blocked"],
            "reason": result.get("reason")
        }
