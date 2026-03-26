# Golem

The **Golem** is an autonomous, long-running entity. Unlike a Knight (which executes a single task and returns), a Golem runs continuously in a background thread, processing tasks from a queue.

---

## Basic Usage

```python
from openclay import Golem, Shield, ClayMemory

golem = Golem(
    name="sentinel",
    llm_caller=my_llm,
    shield=Shield.strict(),
    memory=ClayMemory(),
)

# Start the background event loop
golem.start()

# Submit tasks to the queue
golem.submit("Scan incoming emails for threats")
golem.submit("Summarise today's security events")

# Collect completed results
results = golem.collect()

# Graceful shutdown
golem.stop()
```

---

## Lifecycle Management

```python
golem.start()    # Begin background event loop
golem.pause()    # Temporarily suspend processing (queue preserved)
golem.resume()   # Resume processing
golem.stop()     # Graceful shutdown (finishes current task)
```

### State Properties

```python
golem.is_running   # True while event loop is active
golem.is_paused    # True while paused
```

---

## Synchronous Mode

For one-off tasks without starting the event loop:

```python
result = golem.run("Analyse this document")
print(result.output)
```

---

## Trace Log

A Golem maintains a `TraceLog` across its entire lifetime — every task produces a trace event:

```python
print(golem.trace_log.explain())     # Human-readable summary
print(golem.trace_log.to_json())     # JSON for observability pipelines
print(golem.trace_log.total_count)   # Total events
print(golem.trace_log.blocked_count) # Blocked events
```

---

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `name` | `str` | Identifier for the Golem |
| `llm_caller` | `callable` | Function called as `llm_caller(text, context=...)` |
| `tools` | `list` | Optional `@ClayTool` decorated functions |
| `shield` | `Shield` | Shield instance (defaults to `Shield.strict()`) |
| `memory` | `ClayMemory` | Optional persistent memory (shared across all tasks) |
| `policy` | `Policy` | Optional security policy (overrides shield preset) |
| `trust` | `str` | `"untrusted"` or `"internal"` |

---

## When to Use What

| Primitive | Use Case |
|---|---|
| **Knight** | Single-task execution (API request, one-shot analysis) |
| **Squad** | Multi-step workflows (research → write → review) |
| **Golem** | Always-on monitoring, continuous processing, daemon agents |
