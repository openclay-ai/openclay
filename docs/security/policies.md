# Policies

Policies define your **security posture** — which shield layers are active, what threat threshold triggers a block, and whether to enforce or just observe.

---

## Built-in Presets

### StrictPolicy (Zero Trust)

All layers active, lowest threat threshold. Blocks aggressively.

```python
from openclay import ClayRuntime, StrictPolicy

runtime = ClayRuntime(policy=StrictPolicy())
```

### ModeratePolicy (Balanced)

Production default. Reasonable trade-off between security and throughput.

```python
from openclay import ClayRuntime, ModeratePolicy

runtime = ClayRuntime(policy=ModeratePolicy())
```

### AuditPolicy (Shadow Mode)

Scans everything but **never blocks**. Use this when deploying OpenClay into an existing pipeline to measure impact before enforcing.

```python
from openclay import ClayRuntime, AuditPolicy

runtime = ClayRuntime(policy=AuditPolicy())

result = runtime.run(my_fn, user_input)
# result.blocked is always False
# result.trace contains full analysis — use for monitoring
```

!!! tip "When to use AuditPolicy"
    Use `AuditPolicy` when onboarding OpenClay into production. Run it in parallel with your existing pipeline for a week to see what *would have been blocked*, then switch to `StrictPolicy` or `ModeratePolicy`.

---

## CustomPolicy

Fine-grained control over every aspect of the security posture:

```python
from openclay import ClayRuntime, CustomPolicy

policy = CustomPolicy(
    max_threat_level=0.3,           # Threshold to trigger blocking
    disabled_layers={"rate_limiter"},  # Disable specific layers
    trust_tools=False,              # Shield tool outputs
    auto_block=True,                # Automatically block (False = log only)
)

runtime = ClayRuntime(policy=policy)
```

### CustomPolicy Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_threat_level` | `float` | `0.5` | Threat score above which input is blocked |
| `disabled_layers` | `set` | `set()` | Layers to skip (e.g., `{"rate_limiter", "pii"}`) |
| `trust_tools` | `bool` | `True` | If `False`, tool outputs go through shields |
| `auto_block` | `bool` | `True` | If `False`, threats are logged but not blocked |

---

## Policy Comparison

| Policy | Threshold | Auto Block | Layers | Use Case |
|---|---|---|---|---|
| `StrictPolicy` | 0.1 | ✅ | All | High-security environments |
| `ModeratePolicy` | 0.5 | ✅ | Most | Production default |
| `AuditPolicy` | 0.0 | ❌ | All | Shadow deployment, impact measurement |
| `CustomPolicy` | Custom | Custom | Custom | Fine-grained control |
