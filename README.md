# PromptShields

**Secure AI Applications in 3 Lines of Code**

[![PyPI](https://img.shields.io/pypi/v/promptshields.svg)](https://pypi.org/project/promptshields/)
[![Python](https://img.shields.io/pypi/pyversions/promptshields.svg)](https://pypi.org/project/promptshields/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Downloads](https://pepy.tech/badge/promptshields)](https://pepy.tech/project/promptshields)

Stop prompt injection, jailbreaks, and data leaks in production LLM applications.

---

## Installation

```bash
pip install promptshields
```

## Quick Start

```python
from promptshield import Shield

shield = Shield.balanced()
result = shield.protect_input(user_input, system_prompt)

if result['blocked']:
    print(f"Blocked: {result['reason']} (score: {result['threat_level']:.2f})")
    print(f"Breakdown: {result['threat_breakdown']}")
```

**That's it.** Production-ready security in 3 lines.

---

## Why PromptShields?

| Feature | PromptShields | DIY Regex | Paid APIs |
|---------|---------------|-----------|-----------| 
| **Setup Time** | 3 minutes | Weeks | Days |
| **Cost** | Free | Free | $$$$ |
| **Privacy** | 100% Local | Local | Cloud |
| **F1 Score** | 0.97 (RF) / 0.96 (DeBERTa) | ~0.60 | ~0.95 |
| **ML Models** | 4 + DeBERTa | None | Black box |
| **Async** | ✅ Native | DIY | Varies |

### What We Block
- 🛡️ Prompt injection attacks (direct + indirect)
- 🎭 Jailbreak attempts (DAN, persona replacement)
- 🔑 System prompt extraction
- 🔒 PII leakage
- 📊 Session anomalies
- 🔤 Encoded/obfuscated attacks (Base64, URL, Unicode)

---

## Security Modes

Choose the right tier for your application:

```python
Shield.fast()       # ~1ms  - High throughput (pattern matching only)
Shield.balanced()   # ~2ms  - Production default (patterns + session tracking)
Shield.strict()     # ~7ms  - Sensitive apps (+ 1 ML model + PII detection)
Shield.secure()     # ~12ms - Maximum security (4 ML models ensemble)
```

---

## New in v2.5.0

### Per-Layer Threat Breakdown
Every response now shows exactly which layer triggered:
```python
result = shield.protect_input(user_text, system_prompt)
print(result["threat_breakdown"])
# {"pattern_score": 0.0, "ml_score": 0.994, "session_score": 0.0}
```

### DeBERTa Support
```python
shield = Shield(models=["deberta"])  # Auto-downloads from HuggingFace
```

### Async Support
```python
from promptshield import AsyncShield

shield = AsyncShield.balanced()
result = await shield.aprotect_input(user_text, system_prompt)
```

### FastAPI Middleware
```python
from promptshield import Shield
from promptshield.integrations.fastapi import PromptShieldMiddleware

app.add_middleware(PromptShieldMiddleware, shield=Shield.balanced())
```

### Allowlist & Custom Rules
```python
shield = Shield(
    patterns=True,
    models=["random_forest"],
    allowlist=["summarize this document", "translate to french"],
    custom_patterns=[r"jailbreak|dan mode|evil\s*bot"],
)
```

---

## Benchmark Results

Trained on [neuralchemy/Prompt-injection-dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset):

| Model | F1 | ROC-AUC | FPR | Latency |
|-------|-----|---------|------|---------|
| Random Forest | **0.969** | **0.994** | 6.9% | <1ms |
| Logistic Regression | 0.964 | 0.995 | 6.4% | <1ms |
| Gradient Boosting | 0.961 | 0.994 | 7.9% | <1ms |
| LinearSVC | 0.959 | 0.995 | 10.3% | <1ms |
| DeBERTa-v3-small | 0.959 | 0.950 | 8.5% | ~50ms |

Pre-trained models: [neuralchemy/prompt-injection-detector](https://huggingface.co/neuralchemy/prompt-injection-detector) · [neuralchemy/prompt-injection-deberta](https://huggingface.co/neuralchemy/prompt-injection-deberta)

---

## Documentation

📖 **[Full Documentation](DOCUMENTATION.md)** — Complete guide with framework integrations

🚀 **[Quickstart Guide](QUICKSTART.md)** — Get running in 5 minutes

---

## License

MIT License — see [LICENSE](LICENSE)

---

**Built by [NeurAlchemy](https://github.com/Neural-alchemy)** — AI Security & LLM Safety Research
