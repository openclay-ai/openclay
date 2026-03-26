# Tools

`@ClayTool` intercepts and scans tool outputs **before** they return to the agent's context. This prevents poisoned external data (databases, APIs, web scraping) from hijacking the agent.

---

## The Problem

When an agent calls an external tool (web search, database query, API call), the returned data is blindly injected into the agent's context. If that data contains a prompt injection, the agent is compromised.

**OpenClay solves this** by scanning tool outputs through the shield pipeline before they reach the agent.

---

## Usage

```python
from openclay import ClayTool, Shield, ToolOutputBlocked

@ClayTool(shield=Shield.balanced())
def search_web(query: str):
    return external_api.search(query)

# If the API returns malicious content, it's blocked automatically
try:
    result = search_web("latest AI research")
except ToolOutputBlocked as e:
    print(f"Tool output blocked: {e.trace.reason}")
```

---

## Using the `@tool` Shorthand

```python
from openclay import tool

@tool
def fetch_data(query: str):
    return database.query(query)
```

The `@tool` shorthand uses `Shield.balanced()` by default.

---

## Custom Shield per Tool

Different tools may need different security levels:

```python
@ClayTool(shield=Shield.fast())       # Trusted internal API
def internal_lookup(key: str): ...

@ClayTool(shield=Shield.secure())     # Untrusted web data
def scrape_website(url: str): ...
```
