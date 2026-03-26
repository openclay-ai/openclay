# Knight & Squad

## Knight — Secure Autonomous Entity

A `Knight` is a minimal, secure-by-default agent. It wraps an LLM caller, tools, and memory inside a `ClayRuntime` — every step is shielded.

```python
from openclay import Knight, Shield, ClayMemory, ClayTool

@ClayTool(shield=Shield.balanced())
def search_web(query: str):
    return api.search(query)

knight = Knight(
    name="researcher",
    llm_caller=my_llm_function,
    tools=[search_web],
    shield=Shield.strict(),
    memory=ClayMemory(),
    trust="untrusted",
)

result = knight.run("Find data on AI security")
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `name` | `str` | Identifier for the Knight |
| `llm_caller` | `callable` | Function called as `llm_caller(text, context=...)` |
| `tools` | `list` | Optional list of `@ClayTool` decorated functions |
| `shield` | `Shield` | Shield instance (defaults to `Shield.strict()`) |
| `memory` | `ClayMemory` | Optional persistent memory |
| `trust` | `str` | `"untrusted"` (max shields) or `"internal"` |

### Trust Levels

```python
# Max security — all shield layers active
knight = Knight(name="public", llm_caller=fn, trust="untrusted")

# Reduced shields — for internal, pre-validated data
knight = Knight(name="internal", llm_caller=fn, trust="internal")
```

---

## Squad — Multi-Agent Orchestration

A `Squad` groups multiple Knights under a **master shield**, preventing a compromised Knight from poisoning others.

```python
from openclay import Knight, Squad, Shield

researcher = Knight(name="researcher", llm_caller=research_fn)
writer = Knight(name="writer", llm_caller=writer_fn)

squad = Squad(
    knights=[researcher, writer],
    shield=Shield.secure(),
)

def my_workflow(knights, task):
    research = knights["researcher"].run(task)
    report = knights["writer"].run(research.output)
    return report.output

result = squad.deploy("Analyze AI threat landscape", my_workflow)
```

### How It Works

1. You define Knights with their own individual shields
2. You group them into a Squad with a **master shield**
3. You define a workflow function that receives the knights dict and a task
4. `squad.deploy()` executes the workflow — all inter-Knight data passes through the master shield

This prevents **inter-agent prompt injection** — if the researcher Knight returns malicious output (from a poisoned web source), the master shield intercepts it before it reaches the writer Knight.
