<p align="center">
  <img src="https://raw.githubusercontent.com/neuralchemy/openclay/main/docs/assets/logo.png" alt="OpenClay Logo" width="120"/>
</p>

<h1 align="center">OpenClay</h1>

<p align="center">
  <strong>Secure First → Execute Second.</strong><br/>
  A Neural Alchemy project. The universal, zero-trust execution framework for LLM agents.
</p>

<p align="center">
  <a href="https://pypi.org/project/openclay/"><img alt="PyPI" src="https://img.shields.io/pypi/v/openclay.svg"></a>
  <a href="https://github.com/neuralchemy/openclay"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <a href="https://doc.neuralchemy.in"><img alt="Docs" src="https://img.shields.io/badge/docs-neuralchemy.in-orange"></a>
</p>

---

## Why OpenClay?

Every modern AI framework—LangChain, CrewAI, LlamaIndex—is built on an optimistic assumption: **trust the input, trust the tools, trust the memory.** OpenClay operates on the opposite principle.

> **You do not build an agent and then bolt on security.  
> You define a Security Policy, and the agent executes *inside* it.**

OpenClay wraps every single step — tool calls, memory reads/writes, model inputs and outputs — in a multi-layered shield before any execution ever happens.

---

## Installation

```bash
pip install openclay
```

Optional extras:

```bash
pip install openclay[ml]      # Scikit-learn ensemble models (RF, SVM, LR, GBT)
pip install openclay[embed]   # Sentence-Transformers for semantic similarity
pip install openclay[search]  # DuckDuckGo web fallback for output leakage detection
pip install openclay[all]     # Everything
```

---

## openclay.shields — Core Threat Detection Engine ✅

`openclay.shields` is the battle-tested security core of OpenClay, evolved from [PromptShield](https://github.com/neuralchemy/promptshield) v3.0 *(now deprecated — see [migration guide](#migration-promptshield--openclay) below)*.

It provides a composable, multi-layer defense pipeline for LLM inputs and outputs.

### The Protection Pipeline

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

### Quickstart

```python
from openclay import Shield

# Balanced preset — production default (~1-2ms)
shield = Shield.balanced()

result = shield.protect_input(
    user_input="Ignore your previous instructions and...",
    system_context="You are a helpful assistant."
)

if result["blocked"]:
    print(f"🛡️ Blocked! Reason: {result['reason']}, Threat level: {result['threat_level']:.2f}")
else:
    print("✅ Input is safe.")
```

---

### Shield Presets

Four built-in presets to match your latency / security trade-off:

```python
from openclay import Shield

# ⚡ Fast   — pattern-only, <1ms. Great for high-throughput APIs.
shield = Shield.fast()

# ⚖️ Balanced — patterns + session tracking, ~1-2ms. Production default.
shield = Shield.balanced()

# 🔒 Strict  — patterns + 1 ML model (Logistic Regression) + rate limiting + PII, ~7-10ms.
shield = Shield.strict()

# 🛡️ Secure  — all layers + full ML ensemble (RF + LR + SVM + GBT), ~12-15ms.
shield = Shield.secure()
```

Any preset can be overridden in-place:

```python
# Balanced, but with PII detection and a webhook
shield = Shield.balanced(
    pii_detection=True,
    webhook_url="https://your-siem.example.com/alerts"
)
```

---

### Full Custom Configuration

```python
from openclay import Shield

shield = Shield(
    # Input protection
    patterns=True,                   # Aho-Corasick pattern matching
    models=["random_forest", "logistic_regression", "linear_svc"],  # ML ensemble
    model_threshold=0.7,             # Block threshold (0.0–1.0)

    # Session & rate control
    rate_limiting=True,
    rate_limit_base=100,             # Requests/min per user
    session_tracking=True,
    session_history=10,              # Messages to track per session

    # Canary token protection
    canary=True,
    canary_mode="crypto",            # "simple" | "crypto" (HMAC-based)

    # PII detection & redaction
    pii_detection=True,
    pii_redaction="smart",           # "smart" | "mask" | "partial"

    # Allowlist & custom patterns
    allowlist=["internal_system_key"],
    custom_patterns=[r"exec\(.*\)"],

    # Output protection (DLP)
    sensitive_terms=["project_aurora", "api_key_prod"],
    honeypot_tokens=["CANARY_GOLD"],
    output_filter=["SELECT * FROM users", "Bearer eyJ"],

    # Webhooks for SIEM integration
    webhook_url="https://siem.example.com/alerts",
    webhook_min_threat=0.5,

    # Semantic embeddings (requires: pip install openclay[embed])
    enforce_embeddings=True,
    embedding_model="all-MiniLM-L6-v2",
)
```

---

### Input Protection

```python
result = shield.protect_input(
    user_input=user_message,
    system_context=system_prompt,
    user_id="user_abc",      # For rate limiting
    session_id="sess_123",   # For session anomaly tracking
)

# Result shape:
# {
#   "blocked": bool,
#   "reason": "pattern_match" | "ml_detection" | "rate_limit_exceeded" | "session_anomaly" | ...,
#   "threat_level": float,           # 0.0 – 1.0
#   "threat_breakdown": {
#       "pattern_score": float,
#       "ml_score": float,
#       "session_score": float,
#   },
#   "canary_data": {...},            # Only if canary=True
#   "metadata": {...}
# }
```

---

### Output Protection

```python
result = shield.protect_output(
    model_output=llm_response,
    canary_data=canary_data,  # Pass canary_data from protect_input result
)

# Result shape:
# {
#   "blocked": bool,
#   "reason": "canary_leak" | "sensitive_term" | "output_filter" | "pii_leak" | ...,
#   "output": str | None,  # None if blocked, safe output otherwise
#   "pii_findings": [...],
# }
```

---

### Async Shield

```python
from openclay import AsyncShield

shield = AsyncShield.balanced()

result = await shield.protect_input(
    user_input=user_message,
    system_context=system_prompt,
)
```

---

### Integrations

```python
# ── LangChain ──────────────────────────────────────────────────────────────
from openclay.shields.integrations.langchain import OpenClayCallbackHandler

handler = OpenClayCallbackHandler(shield=shield)
chain = your_chain.with_config(callbacks=[handler])

# ── FastAPI Middleware ─────────────────────────────────────────────────────
from openclay.shields.integrations.fastapi import OpenClayMiddleware

app.add_middleware(OpenClayMiddleware, shield=shield)

# ── CrewAI ────────────────────────────────────────────────────────────────
from openclay.shields.integrations.crewai import OpenClayCrewInterceptor

interceptor = OpenClayCrewInterceptor(shield=shield)

# ── LiteLLM ───────────────────────────────────────────────────────────────
from openclay.shields.integrations.litellm import OpenClayLiteLLMCallback
import litellm

litellm.callbacks = [OpenClayLiteLLMCallback(shield=shield)]

# ── LlamaIndex ────────────────────────────────────────────────────────────
from openclay.shields.integrations.llamaindex import OpenClayLlamaGuard
```

---

### DeBERTa ML Model

For highest accuracy, use the fine-tuned DeBERTa model hosted on Hugging Face:

```python
# Requires: pip install openclay[embed] transformers
shield = Shield(
    patterns=True,
    models=["deberta"],   # Auto-downloads neuralchemy/prompt-injection-deberta on first use
    model_threshold=0.65,
)
```

---

### Custom Components

You can extend the Shield with your own detection logic:

```python
from openclay.shields import ShieldComponent, ShieldResult, register_component

@register_component("my_detector")
class MyDetector(ShieldComponent):
    def check(self, text: str, **context) -> ShieldResult:
        if "bad_word" in text:
            return ShieldResult(blocked=True, reason="custom_rule", threat_level=1.0)
        return ShieldResult(blocked=False)

shield = Shield(custom_components=["my_detector"])
```

---

### YAML Configuration

```python
shield = Shield.from_config("openclay.yml")
```

```yaml
# openclay.yml
patterns: true
canary: true
canary_mode: crypto
rate_limiting: true
rate_limit_base: 100
session_tracking: true
pii_detection: true
models:
  - random_forest
  - logistic_regression
sensitive_terms:
  - project_aurora
webhook_url: https://your-siem.example.com/alert
```

---

## The OpenClay Ecosystem

| Module | Status | Description |
|---|---|---|
| `openclay.shields` | ✅ **Ready** | Core threat detection engine (see above) |
| `openclay.runtime` | 🚧 Draft | Secure execution wrapper for LangChain / CrewAI agents |
| `openclay.tools` | 🚧 Draft | `@tool` decorators — scan tool outputs before returning to agent context |
| `openclay.memory` | 🚧 Draft | Pre-write and pre-read poisoning prevention for RAG and vector databases |
| `openclay.policies` | 🚧 Draft | Explicit, auditable rule engines: `StrictPolicy`, `ModeratePolicy`, `CustomPolicy` |
| `openclay.tracing` | 🚧 Draft | Full explainability and telemetry for every blocked or allowed action |

### Runtime Preview (v0.2.0)

```python
from openclay.runtime import SecureRuntime
from openclay.policies import StrictPolicy

runtime = SecureRuntime(policy=StrictPolicy())
result = runtime.run(my_langchain_agent, user_input="Analyze evil.com")

print(runtime.trace().summary())
```

---

## Migration: PromptShield → OpenClay

`promptshields` (v3.0.1) is now **sunset** and will receive no further updates. All future development happens in `openclay`.

### Step 1 — Update your dependency

```diff
- pip install promptshields
+ pip install openclay
```

### Step 2 — Update your imports

```diff
- from promptshield import Shield
+ from openclay import Shield

- from promptshield.integrations.langchain import PromptShieldCallbackHandler
+ from openclay.shields.integrations.langchain import OpenClayCallbackHandler

- from promptshield.integrations.fastapi import PromptShieldMiddleware
+ from openclay.shields.integrations.fastapi import OpenClayMiddleware

- from promptshield.integrations.litellm import PromptShieldLiteLLMCallback
+ from openclay.shields.integrations.litellm import OpenClayLiteLLMCallback

- from promptshield.integrations.crewai import PromptShieldCrewInterceptor
+ from openclay.shields.integrations.crewai import OpenClayCrewInterceptor
```

### Step 3 — Rename class usages

```diff
- PromptShieldCallbackHandler(shield=shield)
+ OpenClayCallbackHandler(shield=shield)

- PromptShieldMiddleware
+ OpenClayMiddleware

- PromptShieldLiteLLMCallback(shield=shield)
+ OpenClayLiteLLMCallback(shield=shield)

- PromptShieldCrewInterceptor(shield=shield)
+ OpenClayCrewInterceptor(shield=shield)
```

> [!NOTE]
> The core `Shield` API is fully backwards-compatible. Only the integration class names changed.

---

## Links

- 📦 [PyPI — `openclay`](https://pypi.org/project/openclay/)
- 📦 [PyPI — `promptshields` (deprecated)](https://pypi.org/project/promptshields/)
- 📖 [Documentation](https://doc.neuralchemy.in)
- 🤗 [Hugging Face — DeBERTa Model](https://huggingface.co/neuralchemy/prompt-injection-deberta)
- 🐛 [GitHub Issues](https://github.com/neuralchemy/openclay/issues)

---

<p align="center">
  Built with ❤️ by <a href="https://neuralchemy.in">Neural Alchemy</a>
</p>
