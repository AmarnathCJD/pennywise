"""Core module for PennyWise."""

from .enhanced_scanner import EnhancedScanner
from .scanner import ScanResult, Finding
from .results import VulnerabilityFinding
from .target_analyzer import TargetAnalyzer, TargetAnalysis
from .attack_selector import AttackSelector, AttackStrategy, AttackPlan
from .payloads import PayloadLibrary

__all__ = [
    "EnhancedScanner",
    "ScanResult",
    "Finding",
    "VulnerabilityFinding",
    "TargetAnalyzer",
    "TargetAnalysis",
    "AttackSelector",
    "AttackStrategy",
    "AttackPlan",
    "PayloadLibrary"
]
