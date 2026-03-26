# Shields

The core threat detection engine of OpenClay. Every input and output passes through a multi-layered shield pipeline before execution.

---

## The Protection Pipeline

| Layer | Technology | What it catches | Latency |
|---|---|---|---|
| **1. Pattern Engine** | 600+ Aho-Corasick patterns | Injections, jailbreaks, encoding attacks | ~0.1ms |
| **2. Rate Limiter** | Adaptive per-user throttle | Flood / brute-force attacks | ~0.1ms |
| **3. Session Anomaly** | Sliding-window divergence | Multi-turn orchestrated attacks | ~0.5ms |
| **4. ML Ensemble** | TF-IDF + RF / LR / SVM / GBT | Semantic injection variants | ~5-10ms |
| **5. DeBERTa Classifier** | Fine-tuned transformer | Zero-day semantic threats | ~50ms |
| **6. Canary Tokens** | Cryptographic HMAC canaries | System prompt exfiltration | ~0.2ms |
| **7. PII Detector** | Contextual named-entity rules | Sensitive data leakage | ~1ms |
| **8. Output Engine** | Bloom filter + Aho-Corasick + embeddings | Leaked sensitive terms in LLM output | ~2ms |

---

## Shield Presets

Four built-in presets to match your latency / security trade-off:

```python
from openclay import Shield

# ⚡ Fast — pattern-only, <1ms
shield = Shield.fast()

# ⚖️ Balanced — patterns + session tracking, ~2ms (default)
shield = Shield.balanced()

# 🔒 Strict — + ML model + rate limiting + PII, ~7ms
shield = Shield.strict()

# 🛡️ Secure — full ensemble (RF + LR + SVM + GBT), ~12ms
shield = Shield.secure()
```

---

## Input Protection

```python
result = shield.protect_input(
    user_input="Tell me how to hack a system",
    system_context="You are a helpful assistant.",
    user_id="user_123",         # Optional: for session tracking
    session_id="session_abc",   # Optional: for rate limiting
)

if result["blocked"]:
    print(f"Blocked: {result['reason']}")
    print(f"Threat level: {result['threat_level']:.2f}")
```

### Response Format

```python
{
    "blocked": bool,           # Should input be blocked?
    "reason": str,             # "pattern_match", "ml_model", "pii_detected", etc.
    "threat_level": float,     # 0.0 - 1.0
    "metadata": dict,          # Additional context
}
```

---

## Output Protection

Scan LLM outputs for leaked sensitive data:

```python
result = shield.protect_output(
    llm_output="The password is hunter2",
    user_input="What is the admin password?",
)

if result["blocked"]:
    print(f"Output blocked: {result['reason']}")
```

---

## Custom Shield Configuration

```python
shield = Shield(
    patterns=True,
    models=["logistic_regression", "random_forest"],
    model_threshold=0.7,
    session_tracking=True,
    pii_detection=True,
    rate_limiting=True,
    canary=True,
)
```

---

## Async Support

```python
from openclay import AsyncShield

shield = AsyncShield.strict()

result = await shield.protect_input(
    user_input="...",
    system_context="...",
)
```
