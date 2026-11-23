# Synthetic Adversarial Jailbreak Probe & Red-Teaming Engine

[![CI Test Suite](https://github.com/shiv677/synthetic-adversarial-jailbreak-probe/actions/workflows/tests.yml/badge.svg)](https://github.com/shiv677/synthetic-adversarial-jailbreak-probe/actions)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2.13-green.svg)](https://docs.pydantic.dev/)

An automated adversarial evaluation and red-teaming tool designed to audit LLM guardrail robustness, safety refusal accuracy, false positive rates, and secret prompt leak resistance.

## Features
- **Deterministic Mutation Strategies**: Base64 encoding, ROT13 cipher substitution, prefix injection, hypothetical academic framing, and leetspeak obfuscation.
- **Safety Refusal Classifier**: Parses response text for standardized refusal phrases and computes confidence scores.
- **Canary Token Leak Detection**: Audits whether adversarial prompts cause LLMs to leak confidential system instructions or secret tokens.
- **Classification Matrix**: Categorizes each probe into `SAFE_REFUSAL`, `UNSAFE_BYPASS`, `FALSE_POSITIVE_REFUSAL`, `SYSTEM_LEAK`, or `BENIGN_PASS`.

## Quickstart
```bash
pip install pytest pydantic
python main.py --mode standard
pytest -v
```
