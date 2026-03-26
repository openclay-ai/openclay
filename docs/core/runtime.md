# Runtime

`ClayRuntime` is the secure execution wrapper. It fires shields **before** input reaches your function and **after** the output is returned — automatically.

---

## Basic Usage

```python
from openclay import ClayRuntime, StrictPolicy

runtime = ClayRuntime(policy=StrictPolicy())

result = runtime.run(
    my_llm_function,
    "Analyze this data",
    context="You are a research assistant.",
)

if result.blocked:
    print(f"Blocked at layer: {result.trace.layer}")
    print(f"Reason: {result.trace.reason}")
else:
    print(result.output)
```

---

## ClayResult

Every `runtime.run()` returns a `ClayResult`:

| Field | Type | Description |
|---|---|---|
| `output` | `Any` | The function's return value (or `None` if blocked) |
| `blocked` | `bool` | Whether the execution was blocked |
| `trace` | `Trace` | Full explainability record |
| `elapsed` | `float` | Execution time in seconds |

---

## Wrapping Existing Agents

Drop-in shielding for LangChain, CrewAI, or any callable:

```python
wrapped = runtime.wrap(my_langchain_agent)
result = wrapped.run("Research AI security trends")
```

---

## Disabling Layers

Temporarily bypass specific shield layers:

```python
with runtime.disable("input"):
    # Input shield is skipped; output shield still fires
    result = runtime.run(my_fn, trusted_input)
```

---

## Policy Integration

The runtime's behaviour is controlled by a [Policy](../security/policies.md):

```python
from openclay import ClayRuntime, AuditPolicy

# Audit mode: scans everything, blocks nothing
runtime = ClayRuntime(policy=AuditPolicy())

result = runtime.run(my_fn, user_input)
# result.blocked is always False in audit mode
# result.trace still contains full shield analysis
```
