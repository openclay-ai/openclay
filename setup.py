from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="promptshields",
    version="3.0.0",
    author="Neuralchemy",
    author_email="security@neuralchemy.com",
    description="Production-Grade LLM Security Framework - Protect against prompt injection, jailbreaks, and data leakage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Neural-alchemy/promptshield",
    packages=find_packages(include=['promptshield', 'promptshield.*']),
    include_package_data=True,
    package_data={
        'promptshield': [
            'attack_db/*/*.json',
            'attack_db/**/*.json',
            'models/*.pkl',
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.20.0",
        "scikit-learn>=1.0.0",
        "cryptography>=3.4.0",
    ],
    extras_require={
        "dev": ["pytest", "black", "flake8"],
    },
)
