# The Advanced Output Engine

The **Output Engine** is a Phase 2 addition designed for extremely fast Data Loss Prevention (DLP) and string matching mechanisms.

To enable this, install the `[output]` extra:

```bash
pip install promptshield[output]
```

## Multi-Layer Pipeline

PromptShield executes output checks sequentially to minimize latency:

1. **Bloom Filter**: `O(k)` check for massive strings and exact word boundaries.
2. **Aho-Corasick**: `O(n + m + z)` subset substring multi-pattern matching to catch evasions (like zero-width splitters).
3. **Honeypot Tokens**: Catch tokens injected into your Context Window by `Shield.inject_canary()`.
4. **Embedding Fallback**: Uses pre-trained ML to catch syntactically manipulated data variants.

---

### Instantiating

The output engine automatically attaches itself inside `Shield.balanced()` or when passing `sensitive_terms`:

```python
from promptshield import Shield

shield = Shield.balanced(
    sensitive_terms=["internal_db_password", "apikey-1234"],
    honeypot_tokens=["HNY_DB_391"]
)

result = shield.protect_output("Here is the requested DB credentials: internal_db_password")
```
