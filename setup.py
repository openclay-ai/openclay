from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="openclay",
    version="1.0.0",
    author="Neuralchemy",
    description="The Secure-by-Default Execution Framework for LLM Agents.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/neuralchemy/openclay",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "ahocorasick-rs",
        "pyahocorasick",
        "tiktoken",
        "huggingface-hub",
        "tqdm",
    ],
    extras_require={
        "ml": ["xgboost", "scikit-learn", "numpy", "pandas"],
        "embed": ["sentence-transformers", "torch"],
        "search": ["duckduckgo-search"],
        "all": [
            "xgboost", "scikit-learn", "numpy", "pandas",
            "sentence-transformers", "torch", "duckduckgo-search"
        ]
    }
)
