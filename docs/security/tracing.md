# Tracing & Telemetry

Every shield pass produces a `Trace` — a structured, immutable record of exactly what happened. Traces can be exported as JSON for integration with observability pipelines (Datadog, ELK, Splunk, etc.).

---

## Trace

```python
result = runtime.run(my_fn, user_input)

# Human-readable one-liner
print(result.trace.explain())
# → "BLOCKED | layer=input | reason=pattern_match | threat=0.92 | policy=strict"

# Full dictionary
print(result.trace.to_dict())

# Deterministic JSON (for logging pipelines)
print(result.trace.to_json())
```

### Trace Fields

| Field | Type | Description |
|---|---|---|
| `trace_id` | `str` | Unique UUID for this trace |
| `timestamp` | `str` | ISO 8601 timestamp |
| `blocked` | `bool` | Whether execution was blocked |
| `layer` | `str` | Which layer triggered (`"input"`, `"output"`, `"tool"`) |
| `reason` | `str` | Why it was blocked/allowed |
| `threat_level` | `float` | 0.0 - 1.0 |
| `policy_name` | `str` | Active policy name |
| `source` | `str` | Agent name (Knight, Golem) if applicable |

---

## TraceLog

`TraceLog` aggregates traces across multi-step workflows — Knights, Squads, Golems:

```python
from openclay import TraceLog

log = TraceLog()
log.append(result1.trace)
log.append(result2.trace)
log.append(result3.trace)

# Summary
print(log.explain())
print(f"Total: {log.total_count}, Blocked: {log.blocked_count}")
print(f"Max threat: {log.max_threat_level}")

# Full JSON export
print(log.to_json())
```

### Golem Trace Log

Golems maintain a `TraceLog` across their entire lifetime:

```python
golem.start()
golem.submit("Task 1")
golem.submit("Task 2")
golem.stop()

# Every task's trace is recorded
print(golem.trace_log.to_json())
```

---

## JSON Export Format

```json
{
  "total_events": 3,
  "blocked_count": 1,
  "max_threat_level": 0.92,
  "events": [
    {
      "trace_id": "a1b2c3...",
      "timestamp": "2025-03-26T09:00:00Z",
      "blocked": true,
      "layer": "input",
      "reason": "pattern_match",
      "threat_level": 0.92,
      "policy_name": "strict",
      "source": "researcher"
    }
  ]
}
```
