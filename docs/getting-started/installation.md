# Installation

PromptShield is available on PyPI and can be installed using `pip`. It uses optional dependency groups to keep your environment lean.

---

## Basic Installation

Install the core framework with minimum dependencies:

```bash
pip install promptshield
```

> **Note**: This includes exactly what you need for basic heuristics, rule-based scanning, and cryptographic canaries.

## Advanced Installations

PromptShield organizes its integrations and heavy machine-learning models into `extras` to save disk space and reduce bundle size in production environments.

### Install with Integrations
To use the drop-in callbacks for LangChain, LiteLLM, LlamaIndex, or CrewAI:

```bash
pip install promptshield[integrations]
```

### Install with the ML Engine
To enable the advanced embedding-based and XGBoost heuristic pipelines:

```bash
pip install promptshield[ml]
```

### Install with the Output Engine
To enable high-speed Bloom Filters and Aho-Corasick matching for data loss prevention (DLP):

```bash
pip install promptshield[output]
```

### Install with Enterprise Telemetry
To enable OpenTelemetry tracing and metrics out of the box:

```bash
pip install promptshield[telemetry]
```

### The "Everything" Bundle

To install all features, integrations, and ML models at once:

```bash
pip install promptshield[all]
```
