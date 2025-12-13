"""
PennyWise - AI-Powered Vulnerability Scanner
=============================================

An intelligent security analysis tool designed to detect and report
web application vulnerabilities using AI-assisted analysis.

Supported Attack Types:
- XSS (Cross-Site Scripting)
- SQLi (SQL Injection)
- CSRF (Cross-Site Request Forgery)
- Auth Issues (Authentication/Authorization)
- Security Misconfigurations

Core Components:
- AttackSelector: AI-driven attack selection based on target analysis
- SandboxEnvironment: Isolated environment for behavior capture
- BehaviorLearner: Reinforcement learning for user pattern adaptation
- VulnerabilityScanner: Modular scanning engine
"""

__version__ = "2.0.0"
__author__ = "PennyWise Team"

from .core.enhanced_scanner import EnhancedScanner
from .core.attack_selector import AttackSelector
from .core.target_analyzer import TargetAnalyzer
from .sandbox.environment import SandboxEnvironment
from .learning.behavior_learner import BehaviorLearner
from .ai.model_interface import AIModelInterface

__all__ = [
    "VulnerabilityScanner",
    "AttackSelector", 
    "TargetAnalyzer",
    "SandboxEnvironment",
    "BehaviorLearner",
    "AIModelInterface"
]
