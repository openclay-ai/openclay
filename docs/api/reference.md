# API Reference

Complete reference for all public exports from the `openclay` package.

---

## Imports

```python
from openclay import (
    # Shields
    Shield,
    AsyncShield,

    # Runtime
    ClayRuntime,
    ClayResult,
    SecureRuntime,
    WrappedAgent,

    # Tools
    ClayTool,
    ToolOutputBlocked,
    tool,

    # Agents
    Knight,
    Squad,

    # Golem
    Golem,
    GolemResult,

    # Memory
    ClayMemory,
    MemoryWriteBlocked,
    MemoryReadBlocked,

    # Policies
    Policy,
    StrictPolicy,
    ModeratePolicy,
    AuditPolicy,
    CustomPolicy,

    # Tracing
    Trace,
    TraceLog,
)
```

---

## Shield

| Method | Description |
|---|---|
| `Shield.fast()` | Pattern-only, <1ms |
| `Shield.balanced()` | Patterns + session tracking, ~2ms |
| `Shield.strict()` | + ML + rate limiting + PII, ~7ms |
| `Shield.secure()` | Full ensemble, ~12ms |
| `shield.protect_input(user_input, system_context, ...)` | Scan user input |
| `shield.protect_output(llm_output, user_input, ...)` | Scan LLM output |

---

## ClayRuntime

| Method | Description |
|---|---|
| `ClayRuntime(policy=...)` | Create runtime with a security policy |
| `runtime.run(fn, input, context=...)` | Execute function inside shield boundary |
| `runtime.wrap(agent)` | Wrap an existing agent/chain |
| `runtime.disable(layer)` | Context manager to skip a layer |

---

## Knight

| Method | Description |
|---|---|
| `Knight(name, llm_caller, tools=[], shield=..., memory=..., trust=...)` | Create a secure agent |
| `knight.run(task)` | Execute a single task |

---

## Squad

| Method | Description |
|---|---|
| `Squad(knights=[...], shield=...)` | Group Knights under a master shield |
| `squad.deploy(task, workflow_fn)` | Execute a multi-agent workflow |

---

## Golem

| Method | Description |
|---|---|
| `Golem(name, llm_caller, shield=..., memory=..., trust=...)` | Create an autonomous entity |
| `golem.start()` | Start background event loop |
| `golem.submit(task)` | Add task to queue (returns index) |
| `golem.collect()` | Get all completed results |
| `golem.pause()` / `golem.resume()` | Pause/resume processing |
| `golem.stop()` | Graceful shutdown |
| `golem.run(task)` | Synchronous single-task execution |
| `golem.trace_log` | `TraceLog` across lifetime |

---

## ClayMemory

| Method | Description |
|---|---|
| `ClayMemory(shield=...)` | Create shielded memory |
| `memory.save(data)` | Save data (scanned before write) |
| `memory.recall(query)` | Retrieve data (scanned before read) |

---

## Policies

| Class | Threshold | Auto Block | Description |
|---|---|---|---|
| `StrictPolicy()` | 0.1 | ✅ | Zero-trust, all layers |
| `ModeratePolicy()` | 0.5 | ✅ | Production default |
| `AuditPolicy()` | 0.0 | ❌ | Observe-only, never blocks |
| `CustomPolicy(...)` | Custom | Custom | Fine-grained builder |

---

## Trace / TraceLog

| Method | Description |
|---|---|
| `trace.explain()` | One-line human-readable summary |
| `trace.to_dict()` | Dictionary representation |
| `trace.to_json()` | Deterministic JSON string |
| `log.append(trace)` | Add trace to log |
| `log.explain()` | Multi-line summary |
| `log.to_json()` | Full JSON export |
| `log.total_count` | Number of events |
| `log.blocked_count` | Number of blocked events |
| `log.max_threat_level` | Highest threat score |

---

## Integration Classes

```python
from openclay.shields.integrations.langchain import OpenClayCallbackHandler
from openclay.shields.integrations.fastapi import OpenClayMiddleware
from openclay.shields.integrations.litellm import OpenClayLiteLLMCallback
from openclay.shields.integrations.crewai import OpenClayCrewInterceptor
from openclay.shields.integrations.llamaindex import OpenClayLlamaInterceptor
```
