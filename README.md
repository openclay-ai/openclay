<p align="center">
  <img src="https://raw.githubusercontent.com/openclay-ai/openclay/main/docs/assets/logo.png" alt="OpenClay Logo" width="120"/>
</p>

<h1 align="center">OpenClay</h1>

<p align="center">
  <strong>Secure First → Execute Second.</strong><br/>
  The universal, zero-trust execution framework for LLM agents.
</p>

<p align="center">
  <a href="https://pypi.org/project/openclay/"><img alt="PyPI" src="https://img.shields.io/pypi/v/openclay.svg"></a>
  <a href="https://github.com/openclay-ai/openclay"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <a href="https://pepy.tech/projects/openclay"><img alt="Downloads" src="https://static.pepy.tech/badge/openclay"></a>
  <a href="https://pepy.tech/projects/promptshields"><img alt="Legacy Downloads" src="https://static.pepy.tech/badge/promptshields"></a>
  <a href="https://doc.neuralchemy.in"><img alt="Docs" src="https://img.shields.io/badge/docs-neuralchemy.in-orange"></a>
</p>

---

## Why OpenClay?

Every AI framework — LangChain, CrewAI, LlamaIndex — trusts the input, trusts the tools, trusts the memory. OpenClay operates on the opposite principle:

> **You don't build an agent and bolt on security.
> You define a Security Policy, and the agent executes *inside* it.**

---

## Installation

```bash
pip install openclay
```

```bash
pip install openclay[ml]      # ML ensemble (RF, SVM, LR, GBT)
pip install openclay[embed]   # Sentence-Transformers for semantic similarity
pip install openclay[all]     # Everything
```

---

## Quick Start

### Shield (Core Security Layer)

```python
from openclay import Shield

shield = Shield.strict()

result = shield.protect_input(
    user_input="Ignore all previous instructions...",
    system_context="You are a helpful assistant."
)

if result["blocked"]:
    print(f"🛡️ Blocked: {result['reason']}")
```

### ClayRuntime (Secure Execution)

Wrap any LLM call or chain — shields fire automatically on input and output.

```python
from openclay import ClayRuntime, StrictPolicy

runtime = ClayRuntime(policy=StrictPolicy())
result = runtime.run(my_llm, "Analyze this data", context=system_prompt)

if result.blocked:
    print(result.trace.explain())
else:
    print(result.output)
```

### Knight (Secure Agent)

```python
from openclay import Knight, Shield, ClayMemory

knight = Knight(
    name="researcher",
    llm_caller=my_llm,
    tools=[search_web],
    shield=Shield.strict(),
    memory=ClayMemory(),
)

result = knight.run("Find data on AI security")
```

### Squad (Multi-Agent Orchestration)

```python
from openclay import Knight, Squad, Shield

squad = Squad(
    knights=[researcher, writer],
    shield=Shield.secure()  # Master shield prevents inter-agent poisoning
)

result = squad.deploy("Analyze AI threats", my_workflow)
```

### Golem (Autonomous Long-Running Entity)

```python
from openclay import Golem, Shield, ClayMemory

golem = Golem(name="sentinel", llm_caller=my_llm, shield=Shield.strict())

golem.start()
golem.submit("Monitor incoming data for threats")
results = golem.collect()
golem.stop()
```

---

## Core Modules

| Module | Description |
|---|---|
| `openclay.shields` | 8-layer threat detection engine (patterns, ML, DeBERTa, canaries, PII) |
| `openclay.runtime` | Secure execution wrapper — shields before input, shields after output |
| `openclay.tools` | `@ClayTool` decorator — scans tool outputs before they reach the agent |
| `openclay.knights` | `Knight` (single agent) + `Squad` (multi-agent orchestration) |
| `openclay.memory` | `ClayMemory` — pre-write and pre-read poisoning prevention |
| `openclay.policies` | `StrictPolicy`, `ModeratePolicy`, `AuditPolicy`, `CustomPolicy` |
| `openclay.tracing` | `Trace` + `TraceLog` — JSON telemetry for observability pipelines |
| `openclay.golem` | `Golem` — autonomous entity with lifecycle (`start`, `stop`, `pause`, `resume`) |

---

## Shield Presets

```python
Shield.fast()       # ⚡ Pattern-only, <1ms
Shield.balanced()   # ⚖️ Patterns + session tracking, ~2ms (default)
Shield.strict()     # 🔒 + ML model + rate limiting + PII, ~7ms
Shield.secure()     # 🛡️ Full ensemble (RF + LR + SVM + GBT), ~12ms
```

---

## Framework Integrations

```python
from openclay.shields.integrations.langchain import OpenClayCallbackHandler
from openclay.shields.integrations.fastapi import OpenClayMiddleware
from openclay.shields.integrations.litellm import OpenClayLiteLLMCallback
from openclay.shields.integrations.crewai import OpenClayCrewInterceptor
```

---

## Links

- 📖 [Full Documentation](https://doc.neuralchemy.in)
- 📦 [PyPI](https://pypi.org/project/openclay/)
- 🤗 [DeBERTa Model](https://huggingface.co/neuralchemy/prompt-injection-deberta)
- 🐛 [GitHub Issues](https://github.com/openclay-ai/openclay/issues)

---

<p align="center">
  Built by <a href="https://neuralchemy.in">Neural Alchemy</a>
</p>
