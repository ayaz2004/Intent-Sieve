# Intense Sieve 🛡️

AI security framework protecting against prompt injection attacks.

## Quick Start

```bash
# Setup (Windows)
setup_env.bat

# Run test
python test_simple.py

# Run main application
python main.py
```

## What It Does

Protects AI agents from:
- Hidden Unicode attacks (zero-width spaces)
- Injection phrases ("ignore previous instructions")  
- Homoglyph attacks (Cyrillic lookalikes)

## Usage

```python
from src.isolation import ContextualIsolator
from src.detectors import InjectionDetector

isolator = ContextualIsolator()
detector = InjectionDetector()

# Process untrusted input
cleaned, _ = isolator.sanitize(user_input)
threats, risk = detector.analyze(cleaned)

if risk > 0.7:
    print("🚨 Blocked")
else:
    print("✅ Allowed")
```

## Files

```
intense-sieve/
├── main.py              # Main application
├── test_simple.py       # Security tests
├── requirements.txt     # Dependencies
├── setup_env.bat        # Setup script
└── src/
    ├── isolation.py     # Remove hidden chars
    ├── detectors.py     # Detect attacks
    ├── sieve.py         # Risk routing
    ├── agent.py         # AI agent
    └── tools.py         # Agent tools
```

## Requirements

- Python 3.8+
- Ollama with llama3.1:8b and llama-guard3:8b

