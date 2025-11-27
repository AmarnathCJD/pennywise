PennyWise – AI-Powered Vulnerability Scanner
===========================================

PennyWise is an intelligent security analysis tool designed to detect and report
web application vulnerabilities with the assistance of modern AI models.

Currently implemented to detect **XSS** and **SQL Injection (SQLi)** vulnerabilities.

Powered by the **Qwen 2.5 (0.7B)** model as the core inference engine, enabling
context-aware scanning, payload reasoning, and adaptive probing.

Key Capabilities
----------------

- **AI-Assisted Vulnerability Detection** using Qwen-based inference
- **XSS Detection** through payload crafting, injection attempts, and response analysis
- **SQL Injection Detection** via error-based and blind SQLi probing
- **Adaptive Payload Generation** guided by model reasoning
- **Contextual Analysis** of request/response cycles
- **Lightweight Architecture** suitable for developer workflows
- **Modular Design** enabling future integration of CSRF, SSRF, RCE, IDOR, and more

Next-Phase Enhancements
-----------------------

- **Sandbox-Based Behavioral Learning**
  - The tool observes the pentester's workflow inside a controlled sandbox.
  - Learns injection styles, preferred methodologies, and exploration patterns.
  - Adapts scanning behavior to match the user's personal testing strategy.

- **Unified AI Judge**
  - A consolidated evaluation model that classifies findings, reduces noise,
    and rules out false positives across multiple test stages.
  - Merges signals from pattern scanners, payload testers, and model inference.

- **Gemini CLI-Based Vulnerability Finder**
  - CLI integration powered by **Google Gemini** for rapid query-based scanning.
  - Natural-language prompts for generating attack payloads, analyzing responses,
    and producing on-demand security summaries.

Purpose
-------

To build a fast, extensible, and intelligent **web vulnerability scanner** that
leverages AI to enhance detection accuracy, improve workflow adaptability, and
reduce false positives while supporting pentesters in real-world testing scenarios.
