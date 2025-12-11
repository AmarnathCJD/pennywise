# PennyWise - AI-Powered Vulnerability Scanner

<p align="center">
  <pre>
    ╔═╗╔═╗╔╗╔╔╗╔╦ ╦╦ ╦╦╔═╗╔═╗
    ╠═╝║╣ ║║║║║║╚╦╝║║║║╚═╗║╣ 
    ╩  ╚═╝╝╚╝╝╚╝ ╩ ╚╩╝╩╚═╝╚═╝
  </pre>
</p>

<p align="center">
  <strong>AI-Powered Web Application Vulnerability Scanner</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#api">API</a>
</p>

---

## Overview

PennyWise is an intelligent security analysis tool designed to detect and report web application vulnerabilities using AI-assisted analysis. It combines traditional vulnerability scanning techniques with modern machine learning to provide accurate, context-aware security assessments.

### Key Capabilities

- 🔍 **AI-Assisted Vulnerability Detection** - Uses Qwen model for intelligent analysis
- 🎯 **Smart Attack Selection** - Automatically selects optimal attack vectors based on target analysis
- 🧪 **Sandbox Environment** - Isolated environment for capturing user behavior
- 🧠 **Reinforcement Learning** - Adapts to user testing patterns over time
- 📊 **Professional Reports** - Generate HTML, JSON, or Markdown reports
- 🔌 **REST API** - Full-featured HTTP API for integration

## Features

### Attack Types Supported

| Attack | Status | Description |
|--------|--------|-------------|
| XSS | ✅ | Cross-Site Scripting (Reflected, Stored, DOM) |
| SQLi | ✅ | SQL Injection (Error-based, Blind, Union) |
| CSRF | ✅ | Cross-Site Request Forgery |
| Auth | ✅ | Authentication & Authorization Issues |
| SSRF | 🔜 | Server-Side Request Forgery |
| IDOR | 🔜 | Insecure Direct Object References |
| RCE | 🔜 | Remote Code Execution |
| LFI | 🔜 | Local File Inclusion |

### Intelligent Features

- **Target Analyzer**: Fingerprints technologies, forms, parameters, and security headers
- **Attack Selector**: Recommends attacks based on target characteristics
- **Behavior Learner**: Learns from pentester workflows using Q-learning
- **Sandbox**: Captures testing patterns for model training

## Installation

### Prerequisites

- Python 3.10+
- Go 1.21+ (for local model CLI)
- Chrome/Chromium (for Selenium-based testing)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/pennywise.git
cd pennywise

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Build the Go model CLI
go build -o qwen-vuln-detector/localmodel main.go

# Run the server
python app.py server
```

## Usage

### Command Line Interface

```bash
# Start the API server
python app.py server --port 8080

# Scan a target
python app.py scan https://example.com

# Scan with specific attacks
python app.py scan https://example.com --attacks xss sqli

# Aggressive scan mode
python app.py scan https://example.com --mode aggressive

# Analyze without scanning
python app.py analyze https://example.com

# Generate report
python app.py scan https://example.com -o report.html -f html
```

### API Server

```bash
# Start server
python app.py server

# API is available at http://localhost:8080
```

### Python API

```python
import asyncio
from pennywise import VulnerabilityScanner, AttackType
from pennywise.config import PennywiseConfig

async def main():
    config = PennywiseConfig()
    scanner = VulnerabilityScanner(config)
    
    # Run a scan
    result = await scanner.scan(
        url="https://example.com",
        attack_types=[AttackType.XSS, AttackType.SQLI]
    )
    
    # Print findings
    for finding in result.findings:
        print(f"[{finding.severity.value}] {finding.title}")
        print(f"  URL: {finding.url}")
        print(f"  Payload: {finding.payload}")

asyncio.run(main())
```

## Architecture

```
pennywise/
├── pennywise/                 # Main package
│   ├── __init__.py
│   ├── config.py              # Configuration management
│   ├── server.py              # HTTP API server
│   ├── cli.py                 # Command-line interface
│   │
│   ├── core/                  # Core scanning engine
│   │   ├── scanner.py         # Main vulnerability scanner
│   │   ├── target_analyzer.py # Target analysis & fingerprinting
│   │   └── attack_selector.py # Intelligent attack selection
│   │
│   ├── ai/                    # AI model integration
│   │   └── model_interface.py # Qwen model interface
│   │
│   ├── sandbox/               # Behavior capture
│   │   └── environment.py     # Sandbox environment
│   │
│   ├── learning/              # Reinforcement learning
│   │   └── behavior_learner.py # Pattern learning system
│   │
│   └── utils/                 # Utilities
│       ├── logging.py         # Colored logging
│       └── reports.py         # Report generation
│
├── modules/                   # Legacy attack modules
│   └── xss/                   # XSS testing module
│
├── qwen-vuln-detector/        # AI model files
│   ├── localmodel             # Model CLI binary
│   └── adapter_model.safetensors
│
├── app.py                     # Main entry point
├── main.go                    # Go model CLI source
├── index.html                 # Web UI
└── requirements.txt           # Python dependencies
```

## API Reference

### POST /api/scan

Start a vulnerability scan.

```json
{
  "url": "https://target.com",
  "attack_types": ["xss", "sqli"],
  "crawl": true,
  "scan_mode": "active"
}
```

### POST /api/analyze

Analyze a target without active testing.

```json
{
  "url": "https://target.com"
}
```

### GET /api/report/{format}

Generate a report (json, html, markdown, summary).

### POST /api/sandbox/start

Start a sandbox session for behavior capture.

### GET /api/learning/stats

Get learning system statistics.

## Sandbox & Learning

PennyWise includes a sandbox environment that captures pentester behavior:

1. **Start a session**: When you begin testing
2. **Capture actions**: Every attack, payload, and decision is recorded
3. **End session**: Session data is saved
4. **Learn**: The system learns from your patterns

```python
from pennywise.sandbox import SandboxEnvironment
from pennywise.learning import BehaviorLearner

# Start sandbox session
sandbox = SandboxEnvironment()
sandbox.start_session(target_url="https://target.com")

# Your testing actions are captured...
sandbox.capture_attack_start("xss", {"mode": "aggressive"})
sandbox.capture_payload_used("<script>alert(1)</script>", "q", success=True)

# End and learn
sandbox.end_session()

learner = BehaviorLearner(sandbox=sandbox)
learner.learn_from_sandbox()

# Get recommendations based on learned patterns
recs = learner.get_attack_recommendation({"has_forms": True, "has_params": True})
```

## Configuration

Create a `pennywise.json` configuration file:

```json
{
  "scan": {
    "max_pages": 100,
    "max_depth": 5,
    "request_timeout": 15,
    "scan_mode": "active",
    "allowed_hosts": ["localhost", "127.0.0.1"]
  },
  "ai": {
    "model_path": "./qwen-vuln-detector/localmodel",
    "use_local_model": true
  },
  "sandbox": {
    "enabled": true,
    "capture_behavior": true
  },
  "learning": {
    "enabled": true,
    "min_samples": 50
  }
}
```

## Development

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Format code
black pennywise/
isort pennywise/

# Type checking
mypy pennywise/
```

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Powered by Qwen 2.5 model for vulnerability analysis
- Inspired by professional penetration testing workflows
- Built with ❤️ for the security community

---

<p align="center">
  <strong>⚠️ For educational and authorized testing purposes only ⚠️</strong>
</p>
