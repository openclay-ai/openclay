# Installation

## Requirements

- Python 3.8+
- pip

## Install

```bash
pip install openclay
```

## Optional Extras

```bash
pip install openclay[ml]      # Scikit-learn ML ensemble (RF, SVM, LR, GBT)
pip install openclay[embed]   # Sentence-Transformers for semantic similarity
pip install openclay[search]  # DuckDuckGo web fallback for output leakage
pip install openclay[all]     # Everything
```

## Verify Installation

```python
import openclay
print(openclay.__version__)
```

## From PromptShield?

If you are migrating from `promptshields`, update your dependency and imports:

```diff
- pip install promptshields
+ pip install openclay
```

```diff
- from promptshield import Shield
+ from openclay import Shield
```

The core `Shield` API is fully backwards-compatible. See the [API Reference](../api/reference.md) for updated integration class names.
