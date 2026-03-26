# Framework Integrations

OpenClay provides drop-in integration with popular LLM frameworks.

---

## LangChain

```python
from openclay.shields.integrations.langchain import OpenClayCallbackHandler
from openclay import Shield

shield = Shield.strict()

handler = OpenClayCallbackHandler(shield=shield)

# Use with any LangChain chain or agent
chain = LLMChain(llm=my_llm, callbacks=[handler])
```

---

## CrewAI

```python
from openclay.shields.integrations.crewai import OpenClayCrewInterceptor
from openclay import Shield

shield = Shield.secure()

interceptor = OpenClayCrewInterceptor(shield=shield)

# Attach to your CrewAI crew
crew = Crew(agents=[...], interceptor=interceptor)
```

---

## LiteLLM

```python
from openclay.shields.integrations.litellm import OpenClayLiteLLMCallback
from openclay import Shield

shield = Shield.balanced()

callback = OpenClayLiteLLMCallback(shield=shield)

# Use with LiteLLM completion calls
response = litellm.completion(
    model="gpt-4",
    messages=[...],
    callbacks=[callback],
)
```

---

## LlamaIndex

```python
from openclay.shields.integrations.llamaindex import OpenClayLlamaInterceptor
from openclay import Shield

shield = Shield.strict()

interceptor = OpenClayLlamaInterceptor(shield=shield)
```

---

## FastAPI Middleware

```python
from openclay.shields.integrations.fastapi import OpenClayMiddleware
from openclay import Shield
from fastapi import FastAPI

app = FastAPI()
shield = Shield.strict()

app.add_middleware(OpenClayMiddleware, shield=shield)

@app.post("/chat")
async def chat(message: str):
    # Input is automatically scanned by the middleware
    return {"response": my_llm(message)}
```

---

## Manual Integration

For any framework not listed above, use `ClayRuntime` directly:

```python
from openclay import ClayRuntime, StrictPolicy

runtime = ClayRuntime(policy=StrictPolicy())

# Wrap any callable
result = runtime.run(your_framework_call, user_input)
```
